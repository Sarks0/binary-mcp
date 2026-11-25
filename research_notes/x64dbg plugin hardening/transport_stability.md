# Transport & plugin-architecture robustness/stability for binary-mcp's x64dbg integration

Scope: robustness and stability of the transport (MCP server -> `obsidian_server.exe` HTTPS -> single-instance named pipe -> `obsidian.dp64` plugin) and the x64dbg threading constraints that bound what is safe. Security model (loopback bind, auth token, Host/Origin screening, allowlisted commands, no sample launch, 1 MB cap, per-request deadline) must not be weakened. Every claim below is cited; where a recommendation trades safety for responsiveness it is called out explicitly.

---

## Key Question 1 — x64dbg plugin threading model: what is safe off the debugger thread, DbgCmdExec vs DbgCmdExecDirect, and what caused the loader-lock/DEP crashes

### Takeaway
x64dbg is a multi-threaded app (GUI/Qt, command-loop, debug, script, worker, TaskThread). SDK state is protected by internal locks and plugin code must acquire the relevant lock when touching a subsystem; the two command entry points differ fundamentally by thread and sync: `DbgCmdExec` queues a command asynchronously onto the command thread (fire-and-forget, race-prone if you then read results), while `DbgCmdExecDirect` runs the command synchronously and returns only after completion. The in-process HTTP server almost certainly crashed because meaningful work (socket/process/library/lock operations) was performed under loader lock or on a thread that re-entered the loader — exactly the class Microsoft documents as deadlock/instability in DllMain and DLL load paths.

### Cited Findings
- x64dbg's threads: command-loop thread (executes commands sent via the CommandProvider), debug thread (runs the TitanEngine debug loop; between `WaitForDebugEvent` and `ContinueDebugEvent` the debuggee is paused), script thread (simulates user interaction), periodic/one-shot worker threads, a `TaskThread` template helper, and the Qt GUI thread ("the most important (and the most annoying) thread"). — [x64dbg blog: The x64dbg threading model](https://x64dbg.com/blog/2016/10/20/threading-model.html)
- `DbgCmdExec` is relayed to the DBG command loop running in the command thread and "is done asynchronously (meaning DbgCmdExec will not wait until the command is completed)." — [x64dbg blog: Architecture of x64dbg](https://x64dbg.com/blog/2016/10/04/architecture-of-x64dbg.html); [DbgCmdExec SDK docs](https://help.x64dbg.com/en/latest/developers/functions/debug/DbgCmdExec.html)
- `DbgCmdExecDirect` is run "directly in cmddirectexec. This will only return after the command is completed." — [x64dbg blog: Architecture of x64dbg](https://x64dbg.com/blog/2016/10/04/architecture-of-x64dbg.html); [DbgCmdExecDirect SDK docs](https://help.x64dbg.com/en/latest/developers/functions/debug/DbgCmdExecDirect.html)
- x64dbg internals use locks to prevent races; "without them, x64dbg will crash much more often" and developers are told: "Don't forget to acquire the lock when you are accessing a subsystem." — [x64dbg blog: Architecture of x64dbg](https://x64dbg.com/blog/2016/10/04/architecture-of-x64dbg.html)
- Plugin author bug + mrexodia (Duncan Ogilvie, x64dbg author) reply: using `DbgCmdExec` to queue a command then act on the result "causes a race condition"; the fix is `DbgCmdExecDirect`, "which executes the command implementation directly." Ogilvie also warns against calling TitanEngine APIs directly because "x64dbg doesn't know about a breakpoint," and notes "the plugin API is weak in this area." — [n1ght-w0lf: Writing x64dbg plugins (Updates/Comments)](https://n1ght-w0lf.github.io/tutorials/writing-x64dbg-plugins)
- Script-side synchronization: `_plugin_waituntilpaused` works by polling `DbgIsDebugging()`/`dbgisrunning()` with `Sleep(1)` until the debuggee pauses after `debug.Run`/`debug.StepOut` — i.e. the "wait for pause" primitive is itself a poll loop, not an event. — [x64dbg blog: The x64dbg threading model](https://x64dbg.com/blog/2016/10/20/threading-model.html)
- Plugins load serially via `LoadLibrary` + `GetProcAddress("pluginit")`, then `plugsetup`; "Other plugins will be delayed in loading and the x64dbg debugger itself will be waiting for your code to finish," so heavy work in `pluginit`/`plugsetup` stalls the whole debugger. — [x64dbg blog: x64dbg plugin SDK](https://x64dbg.com/blog/2016/07/30/x64dbg-plugin-sdk.html); [n1ght-w0lf: Writing x64dbg plugins](https://n1ght-w0lf.github.io/tutorials/writing-x64dbg-plugins)
- DllMain/loader-lock rules (root cause of the in-process crash class): DllMain runs while the loader lock is held, which sits at the top of the lock hierarchy; you must not call functions that directly or indirectly take the loader lock. Microsoft's explicit risk list includes **creating a process** ("creating a process can load another DLL" -> needs the loader lock you already hold -> deadlock), waiting on other threads, acquiring sync objects owned by waiting code, registry calls, and `CoInitializeEx` (can call `LoadLibraryEx`). — [Microsoft Learn: Dynamic-Link Library Best Practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)
- Lock-ordering deadlock: a thread holding your critical section can block on the loader lock while the loader-lock holder waits on your critical section; "include the loader lock in your lock hierarchy" if DllMain takes any locks. — [Raymond Chen: Another reason not to do anything scary in your DllMain](https://devblogs.microsoft.com/oldnewthing/20040128-00/?p=40853)

### Inferences
- The project's move of the HTTP server out of the plugin is architecturally correct and should not be reversed: an in-process HTTP/TLS listener does socket setup, buffer allocation, thread creation, and often pulls in extra DLLs (Schannel, winsock LSPs) — all of which can re-enter the loader or take locks that conflict with x64dbg's own locks and the loader lock, producing the loader-lock/DEP crashes observed. The out-of-process server + thin pipe client is the safe pattern.
- Because SDK calls are only safe with the right lock held and `DbgCmdExecDirect` runs on the *caller's* thread, the plugin's single pipe-server thread calling `DbgCmdExecDirect` is defensible for correctness (serialized, synchronous, no cross-thread result race) — but it is exactly why one slow handler blocks the whole surface (see Q2). `DbgCmdExec` (async) must never be used where the handler needs to read the command's result.
- Any respawn/watchdog that calls `CreateProcess` must do so from a normal worker thread (as `plugsetup` already is, post-loader) — never from `DllMain`/`DLL_PROCESS_ATTACH`/`DLL_PROCESS_DETACH`.

### Gaps
- No official statement confirms `DbgCmdExecDirect` (cmddirectexec) is safe to call from an *arbitrary* plugin-owned worker thread without additional locking; the architecture post implies the caller's thread runs it and that subsystem locks are the caller's responsibility, but this should be verified against current x64dbg source before fanning out to multiple worker threads. The threading-model and SDK posts are from 2016; current code may differ.
- No primary source enumerates which specific `Dbg*`/`Script*` SDK calls are internally thread-safe vs require caller-held locks. Treat all state-mutating SDK calls as requiring serialization until verified in-source.

---

## Key Question 2 — The blocking long-poll problem (wait-for-pause holds the pipe up to 5 min)

### Takeaway
A single-instance pipe + single server connection means one blocking handler (wait-for-pause) starves status/pause/cancel. The debugger SDK itself exposes "wait for pause" only as a poll loop, so the fix is not a better blocking call but a transport change: separate the control/status/cancel path from the long-running data path, and prefer async event push or a return-a-handle/poll model over a single blocking request that owns the only connection. Real x64dbg automation bridges (x64dbg-automate) use an async PUB/SUB socket design and session IDs rather than one blocking pipe, precisely to allow out-of-band status while long operations run.

### Cited Findings
- `_plugin_waituntilpaused` is implemented as a `Sleep(1)` poll on `DbgIsDebugging()`/`dbgisrunning()` — the SDK's own wait-for-pause is a poll, not a blocking event wait. — [x64dbg blog: The x64dbg threading model](https://x64dbg.com/blog/2016/10/20/threading-model.html)
- x64dbg exposes pause/debug-event state as pollable predicates (`DbgIsDebugging`, `dbgisrunning`) rather than a single blocking "wait" SDK primitive. — [x64dbg blog: The x64dbg threading model](https://x64dbg.com/blog/2016/10/20/threading-model.html)
- x64dbg-automate (a current, independent out-of-process automation bridge) allocates a session ID and a PUB/SUB port per session (e.g. "Allocated PUB/SUB port: 49759"), i.e. an async socket/RPC design with a publish channel for events, not a single blocking request pipe. — [x64dbg-automate session control docs](https://dariushoule.github.io/x64dbg-automate-pyclient/api/session-control); [x64dbg blog: Analysis at Scale with x64dbg Automate](https://x64dbg.com/blog/2025/03/04/analysis-at-scale-with-x64dbg-automate.html)
- Frida's model for long-lived/interruptible sessions: scripts stay loaded during a disconnect and emitted messages are **queued** (buffered), with a bounded reconnect window, rather than one request holding the channel open — i.e. async message push + buffering decouples "work in progress" from "connection held." — [Frida 15.0 release notes](https://frida.re/news/2021/07/18/frida-15-0-released/)
- Overlapped named-pipe mode lets one thread service I/O on *multiple* pipe instances simultaneously and return immediately from read/write/connect; message-mode pipes (`PIPE_TYPE_MESSAGE`/`PIPE_READMODE_MESSAGE`) frame each write as a discrete message. — [Microsoft Learn: CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew)

### Inferences
- Lowest-effort fix that preserves the serial SDK model: convert wait-for-pause into **return-a-handle + poll**. The wait handler should return immediately with a request/operation id; the plugin runs/continues the debuggee and records pause state; the client polls a cheap `status` endpoint. This removes the 5-minute pipe lock without introducing concurrent SDK calls. Because the SDK's own wait is already a poll (`_plugin_waituntilpaused`), nothing is lost in fidelity.
- Medium-effort fix: raise the pipe to **2+ instances** (nMaxInstances >= 2) and reserve one instance exclusively for control/status/cancel, while heavy handlers use the other. Overlapped I/O on multiple instances is the Microsoft-blessed single-thread way to do this. The debug/SDK work still serializes on one plugin worker; only the *transport* is unblocked, so status/cancel remain serviceable during a long run. Tradeoff: slightly more complex pipe lifecycle and the plugin must guarantee only the control instance ever runs concurrently with the data instance (no concurrent SDK mutation).
- Best fit for MCP: async **event push**. The plugin publishes a "paused"/"state-changed" event when the debugger pauses; the server/MCP forwards it. This mirrors both x64dbg-automate's PUB/SUB and Frida's queued-message model and removes long polls entirely. Higher effort on Windows (needs an event channel distinct from request/response).
- A cancellation channel is mandatory for any of these: a long wait must be abortable by an out-of-band message (second pipe instance or a shared cancel flag the plugin worker checks between poll iterations), otherwise cancel cannot be serviced while the data path is busy — which is the current defect.

### Gaps
- No primary source gives a Windows-specific, fully-worked "second reserved pipe instance for control" pattern; it is assembled from the CreateNamedPipe overlapped/multi-instance semantics plus general design. Validate the concurrency safety (only control + one data op in flight) against x64dbg's locking before shipping.

---

## Key Question 3 — Server/plugin liveness: watchdog/respawn, heartbeats, pipe reconnection, idempotency

### Takeaway
There is currently no watchdog to respawn `obsidian_server.exe` if it dies. The robust pattern is: plugin holds the child process handle, waits on it (`WaitForSingleObject` -> `WAIT_OBJECT_0` on exit), and respawns with backoff; wrap the child in a Job Object with kill-on-close so the server can't outlive x64dbg; add a health endpoint; and make retried requests idempotent so a reconnect-and-retry after a half-open pipe is safe. Frida's persist-timeout/resume + message-queuing is the reference design for keeping a session alive across a transient disconnect.

### Cited Findings
- Watchdog/respawn building block: wait on the child's process handle with `WaitForSingleObject`, which returns `WAIT_OBJECT_0` when the process exits — the canonical "detect child death" signal. — [docs.rs uv-windows spawn.rs (WaitForSingleObject on child handle)](https://docs.rs/crate/uv-windows/0.0.45/source/src/spawn.rs)
- Job Objects for lifetime containment: put the spawned process in a job object and monitor it via completion-port messages (process-create/exit, including abnormal-exit codes); a job created with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` terminates its processes when the last handle closes, preventing orphans. Create-suspended -> assign-to-job -> resume avoids a race where the child escapes the job. — [Raymond Chen / Old New Thing: monitoring a process via its job object](https://devblogs.microsoft.com/oldnewthing/20131209-00/?p=2433); [docs.rs uv-windows spawn.rs (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)](https://docs.rs/crate/uv-windows/0.0.45/source/src/spawn.rs)
- Frida session liveness/reconnect reference design: opt-in `persist_timeout` (e.g. `attach(..., persist_timeout=30)`); during a disconnect "scripts will stay loaded on the remote end, but any messages emitted will get queued"; "the client has 30 seconds to reconnect before scripts get unloaded and data is lost"; on the `detached` signal with reason `connection-terminated`, call `session.resume()`, after which "any buffered messages will be delivered." `is_detached` guards the race where `detached` fired before the handler attached. — [Frida 15.0 release notes](https://frida.re/news/2021/07/18/frida-15-0-released/); [Frida Session API](https://frida.re/docs/frida-core/class.Session.html)
- Named-pipe disconnect semantics: an instance is deleted when its last handle closes; a server should not block-read before the client connects (race); a broken connection surfaces as a failed read/write that the server must detect and then `DisconnectNamedPipe`/reconnect. — [Microsoft Learn: CreateNamedPipeW (Remarks)](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew)

### Inferences
- Recommended watchdog: a dedicated plugin worker thread (spawned from `plugsetup`, i.e. after loader lock is released — never from DllMain) holds the server's `PROCESS_INFORMATION.hProcess` and blocks on `WaitForSingleObject`. On `WAIT_OBJECT_0`, respawn with exponential backoff and a cap (e.g. 250 ms -> 5 s, max N restarts/minute to avoid a crash-loop hammering x64dbg). Put the server in a kill-on-close Job Object so x64dbg exit/unload reliably reaps it.
- Half-open pipe detection: the plugin's pipe server must treat any `ReadFile`/`WriteFile` failure (e.g. `ERROR_BROKEN_PIPE`, `ERROR_NO_DATA`, `ERROR_PIPE_NOT_CONNECTED`) as a dropped connection -> `DisconnectNamedPipe` -> `ConnectNamedPipe` to re-arm for the next server connection. Pair with per-request deadlines so a wedged peer cannot pin the single instance forever.
- Idempotency: because a dead server will be respawned and the MCP/server layer may retry, each request should carry a client-generated request id; state-mutating handlers (set breakpoint, continue, write memory) should be safe to replay or should detect a duplicate id and return the prior result. Read-only handlers are naturally idempotent. This is standard retry-safety; cite Frida's buffered-message model as the "don't lose work across a reconnect" precedent.
- Heartbeat/health endpoint: a cheap `health`/`status` request the server answers from its own state (plugin-alive via pipe round-trip, server-alive trivially, debugger-state via a non-blocking SDK predicate) gives the MCP client a liveness signal distinct from a stuck long-poll (ties to Q7).

### Gaps
- No single authoritative "Windows named-pipe reconnect with backoff" reference was found; the reconnect loop is assembled from CreateNamedPipe remarks + general practice. The exact error codes to treat as "peer gone" should be confirmed against the project's pipe code.
- x64dbg-automate's exact RPC/keepalive protocol was not retrievable from docs (it uses PUB/SUB ports but the wire protocol/heartbeat is in-source only). Its source repo (github.com/dariushoule/x64dbg-automate) would be the next stop if a concrete comparator is needed.

---

## Key Question 4 — Concurrency vs serialization: is single-instance pipe + single-connection right?

### Takeaway
For *SDK safety*, serialization is the correct default: x64dbg state is lock-protected and the plugin API is weak around concurrency, so multiple in-flight SDK mutations invite the exact race/crash class the project already fought. The right refinement is not a general worker pool over the SDK, but a narrow split: keep debugger-affecting work serialized on one worker, while adding a *separate*, read-only/control lane (status/cancel/health) so the surface stays responsive. A small fixed worker pool is only safe for independent read-only queries, and only if each SDK call acquires the correct subsystem lock.

### Cited Findings
- x64dbg relies on internal locks to avoid crashing and requires callers to "acquire the lock when you are accessing a subsystem"; without locks it "will crash much more often." — [x64dbg blog: Architecture of x64dbg](https://x64dbg.com/blog/2016/10/04/architecture-of-x64dbg.html)
- Async command dispatch (`DbgCmdExec`) without waiting produces races when results are read; the author recommends the synchronous direct path for correctness. — [n1ght-w0lf: Writing x64dbg plugins (mrexodia reply)](https://n1ght-w0lf.github.io/tutorials/writing-x64dbg-plugins)
- The debug thread owns the paused window between `WaitForDebugEvent`/`ContinueDebugEvent`; GUI work belongs on the Qt thread — i.e. different operations are thread-affine and cannot simply be parallelized. — [x64dbg blog: The x64dbg threading model](https://x64dbg.com/blog/2016/10/20/threading-model.html)
- Overlapped multi-instance pipes let one thread multiplex several connections without a thread-per-connection pool — the transport can be concurrent even while SDK work stays serial. — [Microsoft Learn: CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew)

### Inferences
- Keep SDK calls serialized (single logical debugger-worker). The risk of multiple in-flight SDK calls is memory corruption/crashes because the plugin API does not guarantee internal thread-safety and the project is explicitly warned to hold locks. A general worker pool over arbitrary SDK calls is **not** recommended.
- Decouple *transport concurrency* from *SDK concurrency*: a second pipe instance / overlapped I/O can accept a status or cancel request while the data worker is busy, without ever issuing a concurrent state-mutating SDK call. This is the safe middle ground that fixes responsiveness (Q2) without weakening safety.

### Gaps
- No source quantifies which read-only SDK queries (e.g. register/memory reads) are concurrency-safe against an in-progress operation; treat concurrent reads during a mutation as unsafe absent in-source proof.

---

## Key Question 5 — DoS / resource exhaustion on a localhost TCP + pipe server

### Takeaway
A loopback-only listener still needs defenses against local DoS and, critically, browser-driven cross-origin attacks (DNS rebinding / CSRF) that reach the port from a web page. The project already does the hard parts (loopback bind, auth token, Host/Origin screening, 1 MB cap, per-request deadline). Remaining gaps are concurrency/connection caps, slow-client (slowloris) read timeouts, and keeping Origin validation mandatory even on localhost.

### Cited Findings
- Origin validation is required for local HTTP transports: MCP spec says "Servers MUST validate the Origin header on all incoming connections to prevent DNS rebinding attacks" and SHOULD "bind only to localhost (127.0.0.1) rather than all network interfaces." — [MCP spec: Streamable HTTP transport (security)](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- An unauthenticated localhost server is still exploitable via DNS rebinding unless rebinding protection (Origin/Host checks) is enabled; binding alone does not stop a browser rebinding attack. — [modelcontextprotocol/typescript-sdk advisory GHSA-w48q-cv73-mx4w](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-w48q-cv73-mx4w)
- Host-header allowlisting is the primary DNS-rebinding defense: the service must verify the Host header strictly equals expected values like `127.0.0.1:PORT`/`localhost:PORT` and deny anything else; filtering DNS responses "should not be relied upon as a primary defense." — [NCC Group Singularity: Preventing DNS Rebinding Attacks](https://github.com/nccgroup/singularity/wiki/Preventing-DNS-Rebinding-Attacks)
- CSA (Nov 2026) reinforces that client-side protections should not substitute for server-side Origin checks on MCP transports. — [CSA research note: MCP's Transport Trust Gap](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-transport-trust-gap-20261109-csa-style/)
- Slowloris / slow-request defenses: cap how long the server waits for request headers and return an error (e.g. 408) if the window is missed; a 20–40 s header window with a minimum data rate (~500 B/s) is a typical setting; per-client caps on connections in the read state; lower overall timeouts to drop partial requests sooner (only slightly raises attacker cost). Thread-per-connection servers are the vulnerable class; event-driven ones fare better. Request-side timeouts do not cover slow-*read* (response-stalling) attacks, which need separate send timeouts. — [SEI CMU: Mitigating Slowloris](https://www.sei.cmu.edu/blog/mitigating-slowloris/); [Invicti: Slowloris attack](https://www.invicti.com/learn/slowloris-attack); [Acunetix: Slow HTTP DoS](https://www.acunetix.com/blog/articles/slow-http-dos-attacks-mitigate-apache-http-server/)
- Named-pipe nonpaged-pool exhaustion: every pipe instance reserves in/out buffers from nonpaged pool; the count of instances/threads/processes is limited by available nonpaged pool, so unbounded instances are a local resource-exhaustion vector (a reason the single/small-instance design is defensible). — [Microsoft Learn: CreateNamedPipeW (Remarks)](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew)
- Default named-pipe ACL grants full control to LocalSystem/Administrators/creator-owner and **read access to Everyone and the anonymous account** — so a pipe left with the default descriptor is readable by any local user; a restrictive security descriptor is needed if the IPC is sensitive. — [Microsoft Learn: CreateNamedPipeW (lpSecurityAttributes)](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew)
- `PIPE_REJECT_REMOTE_CLIENTS` (0x8) makes the server automatically reject remote-machine connections — the pipe analog of loopback-only. — [Microsoft Learn: CreateNamedPipeW (dwPipeMode)](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew)

### Inferences
- Keep Origin/Host screening mandatory and strict even though bound to loopback — this is the one defense that stops a malicious web page (DNS rebinding/CSRF) from driving the local debugger port. Do not relax it on the assumption "it's localhost."
- Add a header/first-byte read timeout and an overall connection cap to the server's serial accept loop: a single slow client can currently hold the only connection for the full per-request deadline, which with a 5-minute handler is a trivial local DoS. A short header-read timeout (seconds) separate from the long handler deadline closes the slowloris window without shortening legitimate long operations.
- Set `PIPE_REJECT_REMOTE_CLIENTS` on the plugin pipe and apply a restrictive security descriptor (deny Everyone/anonymous) rather than the default ACL, so a non-admin local user or remote connection cannot speak to `\\.\pipe\x64dbg_mcp`. This hardens the IPC without changing the external security model.
- The existing 1 MB max message size and per-request deadline are correct and should be retained; add an explicit cap on in-flight/queued requests so the bounded event queue cannot be used to build unbounded memory pressure.

### Gaps
- No source gives Winsock-specific socket-option guidance (e.g. `SO_RCVTIMEO` on accept sockets) for slowloris; the mitigations are framed at the HTTP-server/app layer and must be mapped to the project's C++ Winsock accept loop.

---

## Key Question 6 — Graceful shutdown/restart without wedging x64dbg; DLL detach with a request in flight

### Takeaway
Shutdown must not do heavy or blocking work on the DLL-detach/loader path, and must cope with a request in flight. The safe shape: on `plugstop`, signal the worker/watchdog to stop, cancel in-flight work cooperatively, disconnect/close the pipe, and terminate (or let the Job Object reap) the server — all off the loader lock. Never `WaitForSingleObject` on a worker thread from DllMain, and never respawn/CreateProcess during detach.

### Cited Findings
- `plugstop` is called before unloading and is where cleanup belongs; plugins unload/one-at-a-time and x64dbg waits for the plugin's code to finish. — [n1ght-w0lf: Writing x64dbg plugins](https://n1ght-w0lf.github.io/tutorials/writing-x64dbg-plugins); [x64dbg blog: x64dbg plugin SDK](https://x64dbg.com/blog/2016/07/30/x64dbg-plugin-sdk.html)
- Waiting for a thread to exit from DllMain is a classic deadlock: the thread's `DLL_THREAD_DETACH` callback needs the loader lock the waiting DllMain already holds; do not wait on threads or take locks in DllMain. — [Microsoft Learn: Dynamic-Link Library Best Practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices); [Raymond Chen: scary DllMain](https://devblogs.microsoft.com/oldnewthing/20040128-00/?p=40853)
- A named-pipe instance is deleted when its last handle closes; the server must `DisconnectNamedPipe`/`CloseHandle` to release it cleanly, and a blocking read before the peer connects races. — [Microsoft Learn: CreateNamedPipeW (Remarks)](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew)
- Job Object with kill-on-close terminates the child when the last job handle closes — a reliable way to reap the server on x64dbg exit even if orderly shutdown is skipped. — [docs.rs uv-windows spawn.rs](https://docs.rs/crate/uv-windows/0.0.45/source/src/spawn.rs); [Old New Thing: job-object monitoring](https://devblogs.microsoft.com/oldnewthing/20131209-00/?p=2433)

### Inferences
- `plugstop` (not DllMain) should perform shutdown: set a stop event the worker/watchdog polls between operations, cancel the in-flight handler cooperatively (the same cancel path added for Q2), close the pipe handles, then signal the server to exit and/or close the Job Object handle to reap it. Keep `plugstop` bounded (short join timeout) so x64dbg isn't wedged if a worker is stuck.
- DLL-detach with a request in flight: because the server is a separate process, an abrupt x64dbg/plugin teardown leaves the server with a half-open pipe — which the server must detect (failed read/write) and handle by returning an error to the MCP client rather than hanging. The Job Object guarantees the server process itself is reaped even if the plugin crashes.
- Do not respawn during shutdown: the watchdog must distinguish "server exited because we are shutting down" (stop event set -> do not respawn) from "server crashed" (respawn), or a crash-loop/respawn-during-unload can wedge or orphan processes.

### Gaps
- No primary source specifies x64dbg's exact `plugstop` timeout/behavior if a plugin blocks; the "keep plugstop bounded" guidance is inferred from the serial-load/serial-unload warning. Confirm against x64dbg source whether a hung `plugstop` hangs the whole debugger exit.

---

## Key Question 7 — Observability for stability

### Takeaway
A structured health/status response that separately reports plugin-alive, server-alive, pipe-connected, and debugger-state lets the MCP client and operator distinguish a dead server from a busy long-poll from a detached debuggee — which the current single-blocking-channel design cannot. The existing JSONL activity log is the right substrate; add a non-blocking health endpoint and per-request correlation ids.

### Cited Findings
- Debugger state is exposed as cheap, pollable predicates (`DbgIsDebugging`, `dbgisrunning`) usable for a non-blocking health probe. — [x64dbg blog: The x64dbg threading model](https://x64dbg.com/blog/2016/10/20/threading-model.html)
- Frida exposes explicit liveness state (`is_detached` property, `detached` signal with a reason) so a controller can report session health distinctly from in-flight work — a model for structured, multi-field status. — [Frida Session API](https://frida.re/docs/frida-core/class.Session.html); [Frida 15.0 release notes](https://frida.re/news/2021/07/18/frida-15-0-released/)
- MCP transport guidance treats clear server-side state/validation as a first-class reliability/security concern, not optional. — [MCP spec: Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http); [CSA: MCP Transport Trust Gap](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-transport-trust-gap-20261109-csa-style/)

### Inferences
- Health endpoint should be answerable without taking the debugger-worker lock: server-alive and pipe-connected are known at the server/transport layer; plugin-alive is a fast pipe round-trip the plugin answers from its pipe thread without an SDK mutation; debugger-state uses `DbgIsDebugging`/`dbgisrunning`. This makes health immune to the long-poll block (ties to Q2's control lane).
- Attach a request/correlation id to every JSONL log line and every request/response so a retried (idempotent) request and its original can be correlated across a reconnect, and so a stuck handler is visible as "started, no completion" in the log.

### Gaps
- No external source prescribes the exact field set for a debugger-bridge health response; the four-axis model (plugin/server/pipe/debugger) is synthesized from the Frida liveness model + the project's architecture.

---

## Prioritised recommendations (issue -> change -> effort -> risk -> citation)

1. **Blocking long-poll starves status/pause/cancel (5-min pipe lock).** -> Convert wait-for-pause to return-a-handle + cheap poll; OR add a reserved control/status/cancel pipe instance (nMaxInstances>=2, overlapped I/O) kept free of state-mutating SDK calls. -> **M** (handle/poll) to **L** (second instance + event lane). -> Low-Med: must ensure the control lane never issues a concurrent SDK mutation (SDK isn't thread-safe). Trades nothing in security; improves responsiveness. -> [threading model](https://x64dbg.com/blog/2016/10/20/threading-model.html); [CreateNamedPipeW overlapped/multi-instance](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew); [x64dbg-automate PUB/SUB](https://dariushoule.github.io/x64dbg-automate-pyclient/api/session-control)

2. **No watchdog: dead `obsidian_server.exe` is never respawned.** -> Watchdog worker (spawned from `plugsetup`, never DllMain) waits on the server process handle (`WaitForSingleObject` -> `WAIT_OBJECT_0`) and respawns with capped exponential backoff; wrap server in a kill-on-close Job Object. -> **M**. -> Low; must suppress respawn during shutdown (stop-event) to avoid crash-loops/orphans. Security unchanged. -> [WaitForSingleObject child pattern](https://docs.rs/crate/uv-windows/0.0.45/source/src/spawn.rs); [Job object kill-on-close](https://devblogs.microsoft.com/oldnewthing/20131209-00/?p=2433); [DLL best practices (no CreateProcess in DllMain)](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)

3. **No cancellation path for an in-flight long operation.** -> Cooperative cancel flag the debugger-worker checks between poll iterations, settable via the control lane; also used by `plugstop`. -> **M**. -> Low. Enables graceful shutdown too. -> [_plugin_waituntilpaused is a poll loop](https://x64dbg.com/blog/2016/10/20/threading-model.html)

4. **Slowloris / slow-client can hold the single serial connection for the full deadline.** -> Add a short header/first-byte read timeout (seconds) distinct from the long handler deadline, plus a connection/in-flight cap. -> **S**. -> Low; keep separate from the legitimate long-operation deadline so long ops aren't cut off. -> [SEI: Mitigating Slowloris](https://www.sei.cmu.edu/blog/mitigating-slowloris/); [Acunetix slow HTTP DoS](https://www.acunetix.com/blog/articles/slow-http-dos-attacks-mitigate-apache-http-server/)

5. **Named pipe uses default ACL (Everyone/anonymous read) and may accept remote.** -> Set `PIPE_REJECT_REMOTE_CLIENTS` and a restrictive security descriptor (owner-only) on `\\.\pipe\x64dbg_mcp`. -> **S**. -> Low; verify the server process identity matches the ACL. Hardens IPC, no feature loss. -> [CreateNamedPipeW: default ACL + reject-remote](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew)

6. **Half-open pipe not detected -> wedged channel.** -> Treat any pipe read/write failure (`ERROR_BROKEN_PIPE`, etc.) as peer-gone -> `DisconnectNamedPipe` + re-arm; pair with request ids for idempotent retry. -> **M**. -> Low. -> [CreateNamedPipeW Remarks](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew); [Frida buffered-message/resume precedent](https://frida.re/news/2021/07/18/frida-15-0-released/)

7. **No structured liveness signal (can't tell dead vs busy vs detached).** -> Non-blocking health endpoint reporting plugin-alive / server-alive / pipe-connected / debugger-state, answered without the debugger-worker lock; add correlation ids to JSONL + requests. -> **S-M**. -> Low. -> [Frida is_detached/detached model](https://frida.re/docs/frida-core/class.Session.html); [DbgIsDebugging predicate](https://x64dbg.com/blog/2016/10/20/threading-model.html)

8. **Keep Origin/Host screening mandatory even on loopback (DNS rebinding/CSRF).** -> Retain strict Host==127.0.0.1:PORT/localhost:PORT allowlist and Origin check; do not relax because bound to loopback. -> **S** (already present — hold the line). -> None; this is the only defense against a malicious web page reaching the port. -> [MCP spec: MUST validate Origin](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http); [NCC Singularity](https://github.com/nccgroup/singularity/wiki/Preventing-DNS-Rebinding-Attacks); [GHSA-w48q-cv73-mx4w](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-w48q-cv73-mx4w)

9. **Keep SDK calls serialized; do NOT add a general worker pool over SDK calls.** -> Maintain single debugger-worker serialization; only the transport/control/health lane is concurrent. -> **S** (preserve current model). -> High risk if violated: concurrent SDK mutation can crash x64dbg (lock requirement). Explicit safety-over-responsiveness choice. -> [Architecture: acquire locks / crashes without them](https://x64dbg.com/blog/2016/10/04/architecture-of-x64dbg.html); [mrexodia: async DbgCmdExec race](https://n1ght-w0lf.github.io/tutorials/writing-x64dbg-plugins)

10. **Graceful shutdown must not wedge x64dbg.** -> Do cleanup in `plugstop` (signal stop, cancel in-flight, close pipe, reap server/Job Object) with bounded join; never wait on threads or CreateProcess in DllMain. -> **M**. -> Low; keep `plugstop` bounded so a stuck worker can't hang debugger exit. -> [DLL best practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices); [Raymond Chen: DllMain](https://devblogs.microsoft.com/oldnewthing/20040128-00/?p=40853)

### Cross-cutting note on the core design decision
Moving the HTTP/TLS server out of the plugin was correct and must not be reversed: an in-process listener performs socket/TLS/process/lock work that re-enters the Windows loader and collides with x64dbg's own locks — the documented cause of the loader-lock/DEP crash class. Keep the thin out-of-process-server + serialized-SDK core; add responsiveness strictly at the transport/control/observability layers, never by parallelizing SDK calls. — [DLL best practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices); [x64dbg architecture (locking)](https://x64dbg.com/blog/2016/10/04/architecture-of-x64dbg.html)
