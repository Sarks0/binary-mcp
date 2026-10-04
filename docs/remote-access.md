# Remote access

Running the MCP client on one host and the analysis tooling on another. The
usual reason: the debugger and the sample belong in a disposable VM, and the
client does not.

Two arrangements are possible. Only the first is implemented today; the design
and the remaining work for the second are in
[the remote access plan](remote-access-plan.md).

| | What crosses the network | Status |
|---|---|---|
| **Remote MCP server** | The MCP protocol itself. The whole server, Ghidra and x64dbg all live on the debugger host | Implemented |
| **Remote x64dbg bridge** | Only the x64dbg HTTP hop. The server and Ghidra stay with the client | Works through a tunnel; see [below](#remote-x64dbg-through-a-tunnel) |

Throughout: **Host A** is where the MCP client runs, **Host B** is where
x64dbg, the sample and (for the first arrangement) this server run.

---

## Remote MCP server

```
Host A                        Host B
┌──────────────────┐         ┌───────────────────────────────────┐
│ MCP client ──────┼──MCP───▶│ binary-mcp (http transport)       │
└──────────────────┘         │   └─ Ghidra                       │
                             │   └─ x64dbg + obsidian.dp64       │
                             └───────────────────────────────────┘
```

Everything the server touches — the sample, the Ghidra cache, memory dumps,
trace logs — is on one filesystem, so no artifact ends up on the wrong host.

### Option 1: over an SSH tunnel (recommended)

The server keeps its default loopback bind and SSH carries the traffic. SSH
provides the encryption and the host authentication, so no certificates are
needed and no opt-in is required.

**On Host B**, start the server:

```bash
BINARY_MCP_TRANSPORT=http \
BINARY_MCP_HTTP_TOKEN=$(openssl rand -hex 32) \
uv run python -m src.server
```

Keep the token you generated — you need it on Host A. (Leave
`BINARY_MCP_HTTP_TOKEN` unset and the server mints one and logs it at startup,
but it changes on every restart.)

**On Host A**, forward the port and register the server:

```bash
ssh -N -L 8770:127.0.0.1:8770 analyst@host-b &

claude mcp add --transport http binary-mcp http://127.0.0.1:8770/mcp \
  --header "Authorization: Bearer <the token>"
```

The `Host` header a client sends for `127.0.0.1:8770` is accepted, because a
loopback bind accepts `localhost`, `127.0.0.1` and `::1`.

### Option 2: directly on the LAN, with TLS

Use this when a tunnel is impractical. The server refuses to bind a
non-loopback address unless all three of the following are set, and refuses a
wildcard address (`0.0.0.0`, `::`, `*`) under any configuration — name the
interface.

```bash
BINARY_MCP_TRANSPORT=http \
BINARY_MCP_HTTP_HOST=192.168.1.50 \
BINARY_MCP_REMOTE_ALLOW=1 \
BINARY_MCP_REMOTE_TLS_CERT=/etc/binary-mcp/server.crt \
BINARY_MCP_REMOTE_TLS_KEY=/etc/binary-mcp/server.key \
BINARY_MCP_HTTP_TOKEN=<64 hex characters> \
BINARY_MCP_REMOTE_CLIENT_ALLOWLIST=192.168.1.10 \
uv run python -m src.server
```

On Host A:

```bash
claude mcp add --transport http binary-mcp https://192.168.1.50:8770/mcp \
  --header "Authorization: Bearer <the token>"
```

If clients dial a DNS name rather than the address, add it to
`BINARY_MCP_HTTP_ALLOWED_HOSTS` — otherwise the request is refused as a
possible rebinding attempt:

```bash
BINARY_MCP_HTTP_ALLOWED_HOSTS=analysis.lan
```

**Add mutual TLS.** A bearer token is a single secret that travels with every
request. Requiring a client certificate as well means a captured token is not
enough on its own:

```bash
BINARY_MCP_REMOTE_TLS_CA=/etc/binary-mcp/clients-ca.pem
```

A client without a certificate that CA signed now fails the TLS handshake,
before the token is ever read.

### What the listener exposes

A client that authenticates can call every tool: decompile, dump memory, write
debuggee memory, set breakpoints, resume threads. Treat the token as equivalent
to a debugger session on Host B. [Security
model](security.md#the-http-transport) has the full list of what is and is not
enforced; [Configuration](configuration.md#transport) has every key.

Two things worth knowing before you expose it:

- The transport trusts the peer address the socket reports and does not consult
  `X-Forwarded-For`, so `BINARY_MCP_REMOTE_CLIENT_ALLOWLIST` is meaningless
  behind a reverse proxy.
- Path confinement matters more here, not less: the server now shares a
  filesystem with the sample. Set `BINARY_MCP_ALLOWED_DIRS` deliberately.

### Troubleshooting

| Symptom | Cause |
|---|---|
| `Refusing to start: BINARY_MCP_HTTP_HOST=...` | The policy refused the bind. The message names the variable to set; see [Configuration](configuration.md#transport) |
| `401` with `WWW-Authenticate: Bearer` | No token, a malformed `Authorization` header, or the wrong token |
| `400 {"error":"Host not allowed"}` | The client dialed a name the server does not answer for. Add it to `BINARY_MCP_HTTP_ALLOWED_HOSTS` |
| `400 {"error":"Origin not allowed"}` | A cross-origin request, usually a browser. Not served by design |
| `403 {"error":"Client address not permitted"}` | The peer is outside `BINARY_MCP_REMOTE_CLIENT_ALLOWLIST` |

Raise `BINARY_MCP_LOG_LEVEL=DEBUG` on Host B to see each refusal with the
client address and the reason.

---

## Remote x64dbg through a tunnel

The other arrangement — this server and Ghidra on Host A, only the x64dbg hop
crossing the network — works today through an SSH port-forward, with no code
changes. The Obsidian plugin's HTTP server binds Host B's loopback, a forward
terminates on loopback at both ends, and the bridge accepts a token from the
environment instead of its local token file.

**On Host B**, with x64dbg running and the plugin loaded, read the token:

```powershell
Get-Content "$env:TEMP\x64dbg_mcp_token.txt"
```

**On Host A**, forward the port and point the server at the local end:

```bash
ssh -N -L 8765:127.0.0.1:8765 analyst@host-b &

export OBSIDIAN_AUTH_TOKEN=<the token from Host B>
export X64DBG_HOST=127.0.0.1
export X64DBG_PORT=8765
```

Every x64dbg tool then works: memory read and write, breakpoints, stepping,
events, coverage, and `x64dbg_dump_module` (which streams bytes over the API
and writes the file on Host A, where the static tools can reach it).

Two limitations, both from the same cause — some artifacts are written by the
plugin, on Host B:

- `x64dbg_create_minidump`, `x64dbg_dump_memory` and the coverage export land
  in `%TEMP%\obsidian_x64dbg\output\` on Host B. There is no tool to fetch them
  back yet.
- The static side needs the sample on Host A. The Ghidra cache is keyed on the
  SHA-256 of the file's contents, so a copy of the same bytes lines up with
  analysis done on either host.

Phases 3 and 4 of [the plan](remote-access-plan.md) cover the native listener
and artifact transfer that remove both.
