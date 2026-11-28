# Obsidian - External Process Architecture

## Problem Summary

The in-process C++ HTTP server consistently crashed with `BEX64` (Buffer Execution/DEP violation) at fault offset `0x0000000300905a4d`. After extensive debugging and research, this architecture was **fundamentally incompatible** with x64dbg plugin development due to Windows loader lock restrictions.

## New Architecture: External Process Pattern

```
┌──────────────────────────────────────────────────────────┐
│ x64dbg.exe Process                                       │
│                                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │ obsidian.dp64 (Plugin DLL - Minimal Stub)    │   │
│  │                                                  │   │
│  │  • plugsetup() spawns server process           │   │
│  │  • Creates Named Pipe server                   │   │
│  │  • Handles requests from HTTP server           │   │
│  │  • Executes x64dbg API calls                   │   │
│  │  • ~200 lines of code (was ~500)               │   │
│  │                                                  │   │
│  │  [Named Pipe Server Thread]                     │   │
│  │    ↕️ \\.\pipe\x64dbg_mcp                        │   │
│  └──────────────────────┬───────────────────────────┘   │
│                         │                                │
└─────────────────────────┼────────────────────────────────┘
                          │
                          │ CreateProcess() [SAFE]
                          ↓
┌──────────────────────────────────────────────────────────┐
│ obsidian_server.exe Process (Isolated)                │
│                                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │ HTTP Server on port 8765 (TLS optional)         │   │
│  │                                                  │   │
│  │  • Fully isolated process                       │   │
│  │  • No x64dbg dependencies                       │   │
│  │  • Named Pipe client                            │   │
│  │  • Can crash without affecting x64dbg          │   │
│  │  • Easy to debug independently                  │   │
│  │                                                  │   │
│  │  [HTTP Server Thread]                           │   │
│  │    ↕️ TCP 127.0.0.1:8765 (see Listener below)    │   │
│  │                                                  │   │
│  │  [Named Pipe Client]                            │   │
│  │    ↕️ \\.\pipe\x64dbg_mcp                        │   │
│  └──────────────────────────────────────────────────┘   │
│                                                           │
└──────────────────────────────────────────────────────────┘

Communication Flow:
  MCP Client ─HTTP→ Server Process ─Pipe→ Plugin ─x64dbg API→ Debugger
  MCP Client ←HTTP─ Server Process ←Pipe─ Plugin ←Results──── Debugger
```

## Why This Approach Works

### Problems with Old Architecture

| Issue | Old Approach | Result |
|-------|--------------|---------|
| Loader Lock | Created threads in plugsetup() | ❌ Crash/Deadlock |
| DEP Violations | Complex threading in DLL context | ❌ BEX64 error |
| Initialization | Timer delays, complex workarounds | ❌ Still crashed |
| Memory Corruption | Static objects, heap allocations | ❌ Fault 0x905a4d |

### Solutions in New Architecture

| Component | Solution | Result |
|-----------|----------|---------|
| Plugin DLL | Minimal stub, just spawns process | ✅ No loader lock issues |
| HTTP Server | Separate process, complete isolation | ✅ No DEP violations |
| Threading | Server process can use any threading | ✅ No restrictions |
| Debugging | Independent testing of each component | ✅ Easy to diagnose |
| Crashes | Server crash doesn't affect x64dbg | ✅ Fault isolation |

## File Structure

```
src/engines/dynamic/x64dbg/
├── pipe_protocol.h           # Shared pipe constants (name, max message size)
├── plugin/
│   ├── plugin.cpp            # The plugin: spawns the server, owns the pipe,
│   │                         #   dispatches requests, runs the server watchdog
│   ├── event_system.{h,cpp}  # Debug-event queue
│   └── CMakeLists.txt        # Dual-target build (plugin DLL + server EXE), hardened
└── server/
    ├── main.cpp              # HTTP server executable
    ├── listener_policy.h     # Bind / allow-list policy
    ├── schannel_tls.h        # Optional Schannel TLS
    └── activity_log.h        # JSONL activity log
```

The single-process, in-process-server design that caused the crashes above was
replaced, not kept: there is no `plugin_new.cpp`/`plugin_old.cpp` split and no
`http_server.cpp`. `plugin.cpp` is the plugin; `server/main.cpp` is the server.

## Listener

The server binds `127.0.0.1:8765` in plaintext by default, which is what the
diagram above shows. An `obsidian.ini` beside the plugin can move it:

```ini
[listener]
bind=192.168.1.50
port=8765
tls_cert_thumbprint=A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
tls_client_ca_thumbprint=0011223344556677889900AABBCCDDEEFF001122
machine_store=0
allow_clients=192.168.1.10
allow_hosts=analysis.lan
```

The plugin reads it in `SpawnHTTPServer` and forwards the values as command
line flags; the server's policy
(`src/engines/dynamic/x64dbg/server/listener_policy.h`) is what decides whether
the combination is servable. It refuses a wildcard bind outright, refuses a
non-loopback bind with no certificate, and refuses an address it cannot parse
as a dotted quad rather than passing it to `inet_addr`, which accepts forms
the policy does not, and a classifier that disagrees with the thing performing
the bind is one that can be walked past.

A malformed ini fails the whole file rather than dropping one setting, and the
server exits 2 (distinct from its exit 1 for a pipe or port failure) when it
refuses its own configuration.

TLS is Schannel, TLS 1.2 with `SCH_USE_STRONG_CRYPTO`, and the certificate is
named by SHA-1 thumbprint from a Windows certificate store: no PEM parser in
the server, and no new runtime dependency on the binary that gets copied into
an analyst's plugins directory. There is no keep-alive: every request is its
own connection, which is affordable because Schannel's session cache makes a
resumed handshake one round trip, and because every request serialises on the
single named pipe to the plugin anyway.

See [Remote access](remote-access.md) for the setup and
[Security model](security.md#the-plugins-own-listener) for what the listener
enforces.

## Communication Protocol

### Named Pipe Protocol

**Pipe Name:** `\\.\pipe\x64dbg_mcp`

**Message Format:**
```
[4 bytes: length][JSON data]
```

**Request (Server → Plugin):**
```json
{
  "type": 1,  // Protocol::RequestType enum
  "data": {
    // Request-specific data
  }
}
```

**Response (Plugin → Server):**
```json
{
  "status": 0,  // Protocol::Status enum
  "data": {
    // Response data
  }
}
```

### Request Types

Each request carries a numeric `type`. The authoritative list is the
`RequestType` enum in `plugin.cpp`, mirrored by the URL-to-number path table in
`server/main.cpp`; it has grown well past the original handful (there are ~60
types across state, execution, breakpoints, memory, analysis, tracing, events
and health). A few anchors:

| Type | Value | Description |
|------|-------|-------------|
| GET_STATE | 1 | Debugger state (running/paused/not_loaded), with `is_running`, cip, tid |
| READ_MEMORY | 3 | Read process memory |
| EXECUTE_COMMAND | 16 | Execute an allowlisted x64dbg command |
| SET_BREAKPOINT | 20 | Set a software breakpoint |
| GET_HEALTH | 103 | One-call liveness and state snapshot |
| PING | 99 | Health check |

`pipe_protocol.h` defines only the shared pipe constants (`PIPE_NAME`,
`MAX_MESSAGE_SIZE`); its small illustrative `RequestType` enum is historical and
is not what dispatch uses.

## Building and deploying

```bash
cd src/engines/dynamic/x64dbg/plugin
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

**Output (both must live in the same directory):**
- `obsidian.dp64` (or `.dp32`) - plugin DLL
- `obsidian_server.exe` - HTTP server executable

Deploy both into x64dbg's plugins directory, e.g. `C:\x64dbg\x64\plugins\`.
The build applies exploit mitigations (Control Flow Guard, DEP/ASLR, EH
Continuation Guard, CET on the server EXE) and LTCG for Release; see
`CMakeLists.txt` and `research_notes/x64dbg plugin hardening/binary_hardening.md`.

**Smoke test:**
1. Start x64dbg; the log shows `HTTP server process started (PID: ...)` then
   `HTTP server connected to pipe`.
2. `curl -H "Authorization: Bearer $(cat "$TEMP/x64dbg_mcp_token.txt")" http://localhost:8765/health`
   -- `/health` requires the token like every other endpoint.

## Crash isolation and the watchdog

Running the HTTP server in its own process means a server crash cannot take
x64dbg down. To make that isolation useful rather than just survivable:

- The plugin starts a **watchdog thread** (from `plugsetup`, never `DllMain`)
  that waits on the server process and **respawns it with capped backoff** if
  it exits while the plugin is running, clearing the pinned peer PID in between
  so the pipe turns away impostors until the replacement is up.
- The server is assigned to a **job object with `KILL_ON_JOB_CLOSE`**, so a
  crash of x64dbg reaps the server instead of orphaning it.

Both are best-effort and degrade cleanly: if the job cannot be created the
watchdog still respawns, and if the watchdog cannot start the surface still
works, it just will not self-heal after a server crash.

## Advantages

### ✅ Complete Isolation
- Server crashes don't affect x64dbg
- Can restart server without restarting x64dbg
- Memory leaks in server don't affect debugger

### ✅ No Loader Lock Issues
- `CreateProcess()` is safe in plugsetup()
- No threading restrictions in plugin
- Server process has no DLL initialization constraints

### ✅ No DEP Violations
- Separate process space
- No BEX64 errors
- Can use any threading model in server

### ✅ Easy Debugging
- Can test server independently
- Can attach debugger to server process
- Plugin and server have separate logs

### ✅ Proven Pattern
- DbgChild plugin uses this approach
- Matches x64dbg's multi-process design
- Industry standard for plugin isolation

## Evidence & Research

### Successful Examples
1. **DbgChild** - https://github.com/therealdreg/DbgChild
   - Uses external process for helper functions
   - File-based IPC communication
   - Proven stable in production

2. **x64DbgMCPServer (C#)** - https://github.com/AgentSmithers/x64DbgMCPServer
   - C# plugin with HttpListener
   - Works because .NET handles loader lock differently
   - ~20 hours development time vs. weeks debugging C++

3. **x64dbgpy** - Official Python automation
   - External process pattern
   - Stable and widely used

### Failed Approaches
❌ **In-process C++ HTTP server with threading**
- Consistent BEX64 crashes
- Loader lock violations
- No working examples found in x64dbg ecosystem

### Research Sources
- x64dbg Threading Model: https://x64dbg.com/blog/2016/10/20/threading-model.html
- Microsoft DLL Best Practices: https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices
- BEX64 Analysis: Buffer Execution Prevention (DEP) violation
- Fault Analysis: Offset 0x905a4d contains "MZ" header signature

## Performance Considerations

### Inter-Process Communication Overhead
- Named Pipe: ~10-50 microseconds per message
- Negligible for debugging operations
- Much faster than network round-trip

### Process Spawn Time
- ~100-200ms on first start
- One-time cost
- Amortized across debugging session

### Memory Usage
- Plugin DLL: ~100 KB
- Server EXE: ~2-5 MB
- Total: Minimal compared to x64dbg itself

## Troubleshooting

### Server Process Won't Start
**Check:**
1. obsidian_server.exe is in same directory as plugin
2. Check x64dbg log for error messages
3. Try running server manually: `obsidian_server.exe`

### Pipe Connection Failed
**Check:**
1. Only one x64dbg instance running
2. No antivirus blocking Named Pipes
3. Plugin loaded successfully (check x64dbg plugins menu)

### Server Crashes
**Good News:** x64dbg keeps running!
**To Debug:**
1. Run server manually with attached debugger
2. Check server console output
3. Server crash logs don't affect plugin

## Status

This architecture is in place: the out-of-process server, named-pipe IPC,
per-request HTTP handling, the allowlisted command path, the server watchdog,
and the pipe-protocol and higher-level tests all ship today. The historical
to-do list that once sat here (porting the in-process server, wiring the first
handlers) is done; see the handlers in `plugin.cpp`, the routes in
`server/main.cpp`, and the `tests/test_x64dbg_*` suites.

## Conclusion

This external process architecture solves the fundamental incompatibility between complex threading and x64dbg plugin development. It's a proven pattern, easy to maintain, and eliminates all the BEX64/loader lock issues we encountered.

**Result:** Stable, debuggable, production-ready architecture. ✅
