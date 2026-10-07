# Remote access plan: MCP server and Obsidian plugin across hosts

**Status:** Phases 0 to 3 are implemented. See
[Remote access](remote-access.md) for the resulting setup. Phase 4 (artifact
transfer) and Phase 5 (WinDbg user-mode remoting) are still proposed, and two
items inside Phase 3 were deliberately not done — see the notes under it.

## The target topology

Two machines on one LAN:

- **Host A** — the analyst's workstation. Runs the MCP client (Claude Code,
  Claude Desktop, opencode) and, today, the whole `binary-mcp` Python server
  plus Ghidra.
- **Host B** — the disposable Windows VM or second box. Runs x64dbg, the
  `obsidian.dp64` plugin, `obsidian_server.exe`, and the sample.

Everything in this repo currently assumes A and B are the same machine. This
document inventories exactly where that assumption is baked in, then sequences
the work to remove it.

---

## Part 1 — Where the same-host assumption lives

### 1.1 The C++ HTTP server binds loopback, unconditionally — FIXED

`src/engines/dynamic/x64dbg/server/main.cpp:901`

```cpp
serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1 only
```

There is no bind-address argument, no environment variable, and no setting
file. `main()` (`main.cpp:1071-1076`) takes a port from `argv[1]` and defaults
to 8765 — but the plugin never passes one.

### 1.2 The plugin spawns the server with no arguments — FIXED

`src/engines/dynamic/x64dbg/plugin/plugin.cpp:5263-5345` (`SpawnHTTPServer`)
builds the command line as a bare quoted path:

```cpp
snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", serverPath);
```

So the port is always 8765 and the bind address is always loopback, even though
`main()` would accept a different port. The auth token is handed over by
setting `OBSIDIAN_AUTH_TOKEN` in the environment before `CreateProcessA` and
clearing it immediately after (`plugin.cpp:5336`) — a good pattern that already
works for a remote client, see 1.4.

### 1.3 The Python bridge refuses any non-loopback host — FIXED

`src/engines/dynamic/x64dbg/bridge.py:466-471`

```python
allowed_hosts = ("127.0.0.1", "::1", "localhost")
if host not in allowed_hosts:
    raise ValueError("x64dbg bridge only supports loopback connections. ...")
```

`x64dbg_connect(host, port)` (`src/tools/dynamic_tools.py:998-1065`) and
`get_x64dbg_bridge()` (`dynamic_tools.py:393-405`, reading `X64DBG_HOST` /
`X64DBG_PORT`) both plumb a host through to this constructor, which then
rejects anything but loopback. The parameter exists; the gate makes it inert.

Replaced by `resolve_debugger_endpoint` in `src/utils/remote.py`, the same
module the listener's policy lives in. `get_x64dbg_bridge()` no longer reads
`X64DBG_HOST`/`X64DBG_PORT` itself — two readers of one setting is how a
default drifts. A side effect worth noting: the old check accepted `::1` as a
loopback spelling and then built `http://::1:8765`, which is not a URL, so that
spelling had never worked. The endpoint brackets IPv6 literals.

### 1.4 Token provisioning is same-machine by default — but not exclusively

`bridge.py:675-725` (`_read_auth_token`) reads `OBSIDIAN_AUTH_TOKEN` first, and
only falls back to `%TEMP%/x64dbg_mcp_token.txt`. The plugin writes that file
with a current-user-only DACL (`plugin.cpp:5661-5685`,
`BuildCurrentUserOnlySecurity`) and deletes it on unload
(`plugin.cpp:5594-5604`).

**This is the loophole that makes a tunnel work today**: the env var takes
precedence, so a token copied from Host B out-of-band is already accepted on
Host A with no code change. See Part 2.

### 1.5 No transport security at all — FIXED

The wire format is plain HTTP/1.1 with `Authorization: Bearer <64 hex chars>`.
The token is compared in constant time (`main.cpp:242-281`, `SecureCompare`),
which is the right thing for a loopback threat model and almost irrelevant once
the token crosses a LAN in cleartext. There is no TLS, no mTLS, no client-IP
allowlist, and no `Host`-header or `Origin` check — so the moment the listener
leaves loopback it is also exposed to DNS rebinding from a browser on any host
that can resolve a name to Host B's address.

What a stolen token buys an attacker is the full dynamic surface: arbitrary
memory read **and write** in the debuggee (`/api/memory/read`,
`/api/memory/write`, `/api/memory/protect`, `/api/memory/alloc`), register
writes, breakpoints, thread suspend/resume, and the allowlisted command gate.
`docs/security.md` is careful to say no tool can start a sample — that holds,
but it was written for a listener only the local user could reach.

### 1.6 The accept loop serves one connection at a time — STILL TRUE, BY DECISION

`main.cpp:920-947`: a single-threaded `select()` loop with a 1-second accept
timeout, 5-second `SO_RCVTIMEO`/`SO_SNDTIMEO`, a 15-second request deadline
(`REQUEST_DEADLINE_MS`, `main.cpp:454`), a 16 KiB header cap
(`MAX_HEADER_SIZE`, `main.cpp:445`) and a 1 MiB body cap
(`MAX_CONTENT_LENGTH` = `Protocol::MAX_MESSAGE_SIZE`, `main.cpp:450`). Every
connection is closed after one request — no keep-alive.

Over loopback that is fine. Over a LAN it means one round trip per TCP
handshake for each of the dozens of calls a single tool makes, and one slow
client blocks every other. The 1 MiB body cap also caps a single memory write.

**Left as it is, deliberately.** Phase 3 said "keep-alive, or a small thread
pool ... measure before choosing", and measuring needs a Windows host with a
live plugin, which this work did not have. Choosing anyway would have been a
guess, and the two candidates do not deserve equal weight:

* A thread pool buys nothing. Every request serialises on the single named pipe
  to the plugin, and the plugin executes x64dbg API calls on one thread, so
  concurrency at the HTTP layer only moves the queue.
* Keep-alive would help, but less than it first appears: Schannel's session
  cache makes a resumed handshake one round trip with no asymmetric operation,
  which is most of what a per-request handshake costs. Against that, adding
  persistent connections to a hand-rolled HTTP parser adds request-smuggling
  surface — this parser ignores `Transfer-Encoding` entirely, which is harmless
  when every connection closes after one request and is a framing
  vulnerability when it does not.

So the trade is a modest latency win for a class of bug this codebase has
already paid for once (the F-9/F-16 command-splitting work). If a LAN session
turns out to be visibly slow, the fix is keep-alive *plus* explicit rejection of
`Transfer-Encoding` and duplicate `Content-Length`, in one change.

### 1.7 Artifacts: which side of the network a file lands on

This is the part that no amount of socket configuration fixes, and the main
reason a plain tunnel is not the whole answer.

**Already remote-safe** — the plugin streams bytes over HTTP and *Python*
writes the file, so the artifact lands on Host A where the static tools can
reach it:

| Method | Location |
|---|---|
| `dump_module` | `bridge.py:4624-4790` (reads memory, `open(output_path,'wb')` locally) |

**Plugin-side writes** — the path is sent to Host B and the file appears there,
under the plugin's own output root `%TEMP%\obsidian_x64dbg\output\`
(`plugin.cpp:615-656`, `GetOutputRoot`):

| Method | Location | Problem on remote |
|---|---|---|
| `create_minidump` | `bridge.py:992-1019` | Sanitises the path against Host A's `~/.binary_mcp_output/dumps`, then sends that Host-A path to Host B. The confinement check is meaningless and the reported path does not exist on either host in the form it is reported. |
| `dump_memory` | `bridge.py:1749-1790` | Same local-sanitise-then-send-remote mismatch. |
| `export_coverage` | `bridge.py:4592-4619` | Path passed straight through, no sanitisation, lands on B. |
| `start_trace(log_file)` | `bridge.py:3702+`, tool at `dynamic_tools.py:2100-2160` | Already correct in spirit: requires a *relative* name, plugin resolves it inside its own output root, response reports the resolved absolute path. This is the model the other three should follow. |

So on a remote setup today you would get a minidump written somewhere inside
Host B's `%TEMP%`, reported to the model as a Host A path, with no way to fetch
it. `DUMP_OUTPUT_DIR` (`dynamic_tools.py:60`) and the three
`Path.home() / ".binary_mcp_output" / "dumps"` sites in `bridge.py` (lines
1010, 1776, 4678) all encode "the debugger writes where I can read".

### 1.8 Static ↔ dynamic crossover needs the sample on the MCP server's disk

`resolve_cached_binary` (`dynamic_tools.py:441-500`) and the Ghidra project
cache key on the **SHA-256 of the file's contents**, which means the MCP server
process must be able to `open()` the sample. `rebase_static_address` and
`_resolve_module_for_binary` then match Ghidra's view against x64dbg's loaded
modules.

In a split topology the sample lives on Host B. Either it is also present on
Host A (copied once, same bytes → same hash → the cache lines up fine), or the
whole static side is unavailable. This needs to be stated explicitly rather
than discovered.

### 1.9 The MCP server itself is stdio-only — FIXED

`src/server.py:6386-6407` ends in a bare `app.run()`, which is FastMCP's stdio
transport. The client must therefore spawn the server as a subprocess on its
own machine — there is no way for a client on Host A to attach to a server
process on Host B. `fastmcp>=2.13,<3` (`pyproject.toml`) does support
`app.run(transport="http", host=..., port=...)`, so this is a small change
gated mostly on auth and docs.

### 1.10 WinDbg is a different shape

`src/engines/dynamic/windbg/bridge.py` drives dbgeng in-process via Pybag, so
it must run on a Windows host. It already has genuinely remote *kernel*
transports — `connect_kernel_net` (KDNET, `bridge.py:879-937`),
`connect_kernel_serial` (`:938-991`), `connect_kernel_pipe` (`:992-1021`) — and
a local-kernel read-only mode (`connect_kernel_local`, `:1122+`). What it does
*not* have is user-mode dbgeng remoting (`-premote tcp:...`). So for WinDbg,
"remote" means either topology B below, or a separate dbgeng-remoting project.

### 1.11 Configuration keys are documented wrong — FIXED

`src/utils/config.py:193` declares:

```python
"X64DBG_BRIDGE_URL": "URL for x64dbg HTTP bridge (default: http://localhost:27042)",
```

Nothing reads `X64DBG_BRIDGE_URL`. The code reads `X64DBG_HOST` and
`X64DBG_PORT` (`dynamic_tools.py:400-401`) and the real default port is 8765,
not 27042. The wrong key and wrong port are repeated in
`docs/configuration.md:22` and `.env.example:29`. Any remote configuration
story has to start by fixing this, or operators will set a variable that does
nothing.

### 1.12 Installers assume one machine

`install.py:1112-1196` writes a Claude Desktop / Claude Code config whose
`command` spawns the server locally. `install.ps1:1274-1381` deploys
`obsidian.dp64`, `obsidian.dp32` and `obsidian_server.exe` into x64dbg's plugin
directories, with release-digest verification. Neither has a notion of "install
the debugger half here and the analysis half there", and neither opens a
firewall port (correctly, today — there is nothing to expose).

---

## Part 2 — What already works: tunnelled remote, zero code changes

Worth doing first, because it is free and it validates the rest of the plan
against a real two-host setup.

Because the C++ server binds Host B's loopback, and an SSH port-forward
*terminates* on loopback at both ends, and `OBSIDIAN_AUTH_TOKEN` takes
precedence over the token file, the existing code already supports:

```powershell
# On Host B (Windows): enable OpenSSH Server once, then read the token
Get-Content "$env:TEMP\x64dbg_mcp_token.txt"
```

```bash
# On Host A: forward B's loopback 8765 to A's loopback 8765
ssh -N -L 8765:127.0.0.1:8765 analyst@host-b

# Then point the MCP server at the local end of the tunnel
export OBSIDIAN_AUTH_TOKEN=<token from Host B>
export X64DBG_HOST=127.0.0.1
export X64DBG_PORT=8765
```

The bridge connects to `127.0.0.1:8765`, passes its own loopback check, and
SSH carries the traffic — authenticated, encrypted, and with no new listener on
the LAN.

**What works:** every read/write/control endpoint, the command gate, events,
coverage collection, `dump_module` (lands on Host A).

**What does not:** `create_minidump`, `dump_memory` and `export_coverage` write
on Host B and report a Host A path (1.7); the static side needs a copy of the
sample on Host A (1.8).

Deliverables for this phase are documentation plus two tests — one that
`OBSIDIAN_AUTH_TOKEN` genuinely bypasses the token file, one that the three
mismatched artifact methods are at least *honest* about which host they wrote
on.

---

## Part 3 — Two topologies, and which to build

### Topology A — remote Obsidian bridge

MCP server + Ghidra stay on Host A; only the x64dbg HTTP hop crosses the
network.

```
Host A                                   Host B
┌──────────────────────────┐             ┌──────────────────────────┐
│ MCP client (stdio)       │             │ x64dbg.exe               │
│   └─ binary-mcp (Python) │             │   └─ obsidian.dp64       │
│        └─ Ghidra         │             │        ↕ named pipe      │
│        └─ X64DbgBridge ──┼──TLS/LAN───▶│ obsidian_server.exe      │
└──────────────────────────┘             └──────────────────────────┘
```

- **For:** keeps the analysis brain and the sample's static copy outside the
  malware VM; Ghidra runs on the beefier host; the VM stays thin and revertible.
- **Against:** needs TLS + token provisioning in C++, needs artifact transfer
  (1.7), needs the sample on both hosts (1.8).

### Topology B — remote MCP server

The whole of `binary-mcp` runs on Host B next to x64dbg; the client on Host A
speaks MCP over HTTP.

```
Host A                        Host B
┌──────────────────┐         ┌───────────────────────────────────┐
│ MCP client ──────┼─MCP/TLS▶│ binary-mcp (FastMCP http)         │
└──────────────────┘         │   └─ Ghidra                       │
                             │   └─ X64DbgBridge → 127.0.0.1:8765│
                             │ x64dbg.exe + obsidian.dp64        │
                             └───────────────────────────────────┘
```

- **For:** every filesystem coupling in 1.7 and 1.8 disappears, because the
  debugger, the sample, the Ghidra cache and the output root are all on one
  machine. The C++ server never leaves loopback, so §1.5 and §1.6 stay out of
  scope. WinDbg becomes usable remotely for free (1.10).
- **Against:** Ghidra and a JVM inside the malware VM; the MCP server's own
  listener now needs auth and TLS; path confinement
  (`BINARY_MCP_ALLOWED_DIRS`) has to be re-reasoned for a host where the
  sample and the server share a filesystem.

### Recommendation

Build **B first, then A.** B is a far smaller change (one transport call, one
auth provider, docs) and it is the one that fully solves the stated scenario
without leaving artifacts stranded. A is the better long-term posture for
malware work — analysis brain outside the infected VM — but it is only
*complete* once artifact transfer and path-origin semantics exist, which is
Phase 4 below. Both share Phase 1.

---

## Part 4 — Phased implementation

### Phase 0 — Fix the configuration surface (prerequisite, ~small) — DONE

| Change | Files |
|---|---|
| Delete `X64DBG_BRIDGE_URL`; document `X64DBG_HOST`, `X64DBG_PORT` with the real 8765 default | `src/utils/config.py:193`, `docs/configuration.md:22`, `.env.example:29` |
| Add a test asserting every `X64DBG_*` key in `CONFIG_KEYS` is read somewhere in `src/` | `tests/test_docs_accuracy.py` |

Doing this first means the remote keys added later land in a surface that is
actually true. The new test is the thing that stops key #11 recurring.

### Phase 1 — Shared remote groundwork — DONE

- **Done.** `src/utils/remote.py` parses and validates a remote endpoint
  (host, port, TLS material, token, Host allow-set, client allowlist) from one
  documented set of variables, and carries the ASGI gate that enforces them.
  Phase 3 reuses the same parser for the bridge so the two cannot drift.
- **Done.** New env keys, all off by default: `BINARY_MCP_REMOTE_ALLOW`
  (master switch), `BINARY_MCP_REMOTE_TLS_CERT`, `_KEY`, `_CA` and
  `BINARY_MCP_REMOTE_CLIENT_ALLOWLIST`, plus the transport's own
  `BINARY_MCP_TRANSPORT`, `_HTTP_HOST`, `_HTTP_PORT`, `_HTTP_PATH`,
  `_HTTP_TOKEN` and `_HTTP_ALLOWED_HOSTS`.
- **Done.** `docs/security.md` has a `## The HTTP transport` section stating
  the new threat model in the same plain terms as the rest of that file, and
  `docs/remote-access.md` is the operator guide.
- **Done (the bridge half).** `resolve_debugger_endpoint` replaces the hard
  loopback check at `bridge.py:466-471`, with the same fail-closed posture and
  the same opt-in variable: a non-loopback host needs `BINARY_MCP_REMOTE_ALLOW`,
  `X64DBG_TLS_CA` and `OBSIDIAN_AUTH_TOKEN`. `verify=` and `cert=` reach the
  `requests` calls, and the plugin's `%TEMP%` token file is consulted only for
  a loopback endpoint. One shared exception base, `RemoteConfigError`, with
  `TransportConfigError` and `DebuggerEndpointError` under it.

### Phase 2 — Topology B: remote MCP transport — DONE

| Change | Files |
|---|---|
| `main()` chooses transport from config: stdio (default) or `transport="http"` with an explicit bind host and port | `src/server.py:6386-6407` |
| Refuse to bind a non-loopback address without `BINARY_MCP_REMOTE_ALLOW` + TLS material | `src/server.py`, `src/utils/remote.py` |
| Bearer-token auth on the MCP listener, token minted at startup and printed once to stderr; constant-time compare | new middleware |
| `Host`/`Origin` validation against the configured bind name, to close DNS rebinding | new middleware |
| Re-document `BINARY_MCP_ALLOWED_DIRS` for the co-resident case: the server now shares a filesystem with the sample, so the quarantine allow-list matters more, not less | `docs/security.md`, `docs/configuration.md` |
| Client-side config example for Host A | `config/`, `docs/claude-code-setup.md` |

Tests: refuses non-loopback bind without the switch; refuses without TLS;
rejects a missing/wrong token; rejects a mismatched `Host` header; stdio
remains the default when nothing is set.

### Phase 3 — Topology A: remote Obsidian listener — DONE

**Policy** — new, and the reason the rest of this could be verified at all.
`src/engines/dynamic/x64dbg/server/listener_policy.h` holds every decision as a
string or integer decision, with no Windows headers, so
`tests/test_cpp_listener_policy.py` compiles the shipped header with g++ and
*runs* it. It refuses a wildcard bind with or without TLS, refuses a
non-loopback bind with no certificate, refuses an address it cannot parse as a
dotted quad (rather than handing it to `inet_addr`, which accepts `0`, `127.1`
and `0177.0.0.1` — a classifier that disagrees with the thing performing the
bind is one that can be walked past), validates thumbprints and ports, and
parses the client allowlist.

**C++ server** (`server/main.cpp`)

- `--bind`, `--port`, `--tls-cert-thumbprint`, `--tls-client-ca-thumbprint`,
  `--machine-store`, `--allow-client`, `--allow-host`. The legacy positional
  port still works, because deployed plugins may still pass it.
- TLS via Schannel (`server/schannel_tls.h`): TLS 1.2 with
  `SCH_USE_STRONG_CRYPTO`, certificate named by SHA-1 thumbprint from a
  Windows store, so there is no PEM parser in the process and no new runtime
  dependency on a binary that gets copied into an analyst's plugins directory.
  Mutual TLS pins the client chain to one CA thumbprint rather than accepting
  anything the machine's trust stores would.
- The client allowlist is checked at `accept()`, before the handshake, before
  any HTTP is parsed, and before the token is compared.
- `Host` and `Origin` are validated before the token, and the
  `Access-Control-Allow-Origin: *` that used to be on every response —
  including the 401 — is gone. `OPTIONS` is no longer exempt from
  authentication, there being no preflight left to serve. **This was not in the
  original plan**; §1.5 named the missing Host check as a finding and it would
  have been a live rebinding hole the moment the listener left loopback.
- `server.start` in the activity log carries the resolved listener, so a log
  from a LAN-exposed mutual-TLS run does not read like one from the loopback
  default.
- TLS is introduced behind a `Connection` abstraction whose `Recv`/`Send` keep
  `recv`/`send` semantics exactly, so the audited request-reading loop (the
  F-19 header, body and deadline bounds) did not change. Rewriting that loop to
  suit a new transport is how those bounds would have been lost.

**Plugin** (`plugin/plugin.cpp`)

- Reads `obsidian.ini` beside the plugin with `GetPrivateProfileString` and
  forwards the values as flags. An ini rather than `BridgeSettingGet`: plain
  Win32 with no SDK surface to track, editable without x64dbg's settings
  dialog, and next to the server executable and its log where someone looking
  for it will look. Default unchanged — no ini means loopback, 8765, no TLS.
- Values are restricted to the characters their flag can hold, and a violation
  refuses the **whole file**. The server validates thumbprints and addresses,
  but only after the command line has been split; a value carrying a space or a
  quote could otherwise smuggle a second flag past the one being set.
- The effective listener goes in the x64dbg log at startup, with an explicit
  note when the bind is not loopback.
- Exit code 2 from the server (configuration refused) is reported distinctly
  from exit 1 (ran and stopped): retrying will not help and the pipe is not the
  problem.

**Python bridge** — done in Phase 1; nothing left. It already dialled an
`https` endpoint and verified it against `X64DBG_TLS_CA`, so this phase needed
no Python change at all: an operator drops the TLS terminator and points
`X64DBG_HOST` at the plugin.

**Installer / release** — two deviations, both deliberate:

- The planned `install.ps1 -RemoteListener` mode became a documented command
  sequence in [Remote access](remote-access.md) instead. There is no PowerShell
  on any runner this work could reach, so the script could not have been
  syntax-checked, let alone run — and an unverifiable installer that creates
  certificates and firewall rules is a worse outcome than commands an operator
  pastes one at a time and sees the result of. The two properties that make the
  sequence safe rather than merely convenient (`-RemoteAddress` on the firewall
  rule, never a wildcard bind in an example) are pinned by
  `tests/test_cpp_listener_policy.py`, as is the correspondence between the
  documented `[listener]` keys and the ones the plugin actually reads.
- The planned `install.py` split-host mode is **not done**. It would write a
  bearer token into a `.env` on the analyst's behalf; the six documented
  environment variables are clearer, and where a debugger token lands should be
  a deliberate act. Say so rather than leave it looking forgotten.
- `release.yml` needs no change: `secur32` and `crypt32` ship with Windows, so
  the server gains no new link-time artifact and the static-runtime property
  ("no VC++ Redist required") still holds. The `build-plugin` job in `ci.yml`
  compiles both architectures with warnings-as-errors on every pull request,
  which is what will first exercise this C++ for real.

**What is verified, and what is not.** The policy header is compiled and run on
Linux (~90 decisions). `schannel_tls.h` and the changed `main.cpp` were
type-checked against stub Windows headers, which catches typos, wrong member
names and sign defects but cannot catch a misremembered Win32 signature.
Neither has been executed. The first real test is the CI compile job, which
runs on a pull request to `main` or `develop` — not on a branch push.

### Phase 4 — Artifact transfer and path-origin semantics

This is what makes Topology A actually usable, and it is independently useful
on a single host because it removes the "reported a path it did not write"
class of bug that §1.7 still contains.

- Make `start_trace`'s contract the universal one: **plugin-written artifacts
  take a relative name, are confined to the plugin's output root, and the
  response reports the resolved absolute path.** Apply to `create_minidump`
  (`bridge.py:992-1019`), `dump_memory` (`:1749-1790`), `export_coverage`
  (`:4592-4619`). Stop sanitising a remote path against a local directory.
- New plugin endpoints `/api/artifact/list` and `/api/artifact/fetch` (chunked
  read, confined to the output root via the existing `GetOutputRoot` +
  reparse-point checks) so the bridge can pull an artifact to Host A and hand
  the static tools a local path.
- A `host` field on every artifact-producing tool's response — `"local"` or the
  remote endpoint — so the model is never told a file is somewhere it is not.
- For Phase 2 (Topology B) this is a no-op, since local *is* the debugger host:
  one more reason to sequence B first.

### Phase 5 — WinDbg remote (optional, later)

Topology B covers WinDbg already. Native user-mode dbgeng remoting
(`-premote tcp:port=...,server=...`, mirroring the existing
`connect_kernel_net`/`_serial`/`_pipe` family at
`windbg/bridge.py:879-1021`) is a separate piece of work with its own command
gate implications — `windbg_execute_command` is already off unless
`BINARY_MCP_ENABLE_RAW_WINDBG=1`, and a remote target changes what "read-only
inspection" means. Not in scope until A and B are both landed.

---

## Part 5 — Test plan

New test modules, mirroring the existing naming:

| File | Covers |
|---|---|
| `tests/test_remote_policy.py` | The Phase 1 parser: fail-closed on non-loopback without the switch, without TLS, without a CA; loopback unaffected |
| `tests/test_remote_bridge.py` | `X64DbgBridge` accepts a remote `https` host under policy, passes `verify=`, refuses `http`, does not touch the local token file when remote |
| `tests/test_remote_mcp_transport.py` | `src/server.py` defaults to stdio; http transport refuses a non-loopback bind without the switch; token and `Host` checks |
| `tests/test_artifact_origin.py` | Every artifact-producing tool reports the host it wrote on; plugin-side methods take relative names only |
| `tests/test_cpp_remote_args.py` | Extend `tests/test_cpp_request_parsing.py`'s approach: parse `main.cpp` to assert the default bind is still loopback and `0.0.0.0` is refused |

Extend existing suites:

- `tests/test_docs_accuracy.py` — every new `BINARY_MCP_REMOTE_*` key is named
  in `docs/configuration.md` and `docs/security.md`; the loopback-by-default
  claim is pinned against the code, the same way the confinement and symbol
  claims already are.
- `tests/test_installer_integrity.py` — the new installer mode does not weaken
  digest verification, and the firewall rule is never created with scope `Any`.
- `tests/test_confinement_sweep.py` / `tests/test_path_confinement.py` — the
  co-resident Topology B case.

Manual two-host validation, in order: Part 2 tunnel first (proves the protocol
works across a network at all), then Topology B, then Topology A.

---

## Part 6 — Open questions

1. **Does Topology A pay for itself?** If the answer for most users is "install
   everything in the VM and connect Claude to it", Phase 3 and 4 are a lot of
   C++ and artifact plumbing for a minority topology — and the Part 2 tunnel
   already covers the determined user. Worth deciding before writing Schannel
   code.
2. **mTLS or token-over-TLS?** mTLS is the honest answer for a listener that
   grants arbitrary debuggee memory writes. It is also the one most likely to
   go unconfigured and push people back to the tunnel.
3. **Is the 1 MiB `MAX_CONTENT_LENGTH` (`main.cpp:450`, shared with
   `Protocol::MAX_MESSAGE_SIZE`) a real ceiling on remote writes**, and does
   lifting it belong in this work or separately?
4. **Should remote mode narrow the command allowlist?** The x64dbg gate is
   fail-closed and read-biased already, but it was written assuming the caller
   is the local user.
