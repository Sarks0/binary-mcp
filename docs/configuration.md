# Configuration

Settings come from the environment or from a `.env` file in the project root;
the environment wins. Copy [`.env.example`](../.env.example) to `.env` to
start.

The full list of keys and their descriptions lives in `CONFIG_KEYS` in
[`src/utils/config.py`](../src/utils/config.py). The keys worth knowing are
below.

## Engines

| Variable | Description | Default |
|----------|-------------|---------|
| `GHIDRA_HOME` | Ghidra installation path | Auto-detected |
| `GHIDRA_INSTALL_DIR` | Alias for `GHIDRA_HOME`, the name Ghidra's own tooling uses. Checked second | Unset |
| `GHIDRA_TIMEOUT` | Analysis timeout in seconds (30-3600) | 1800 |
| `GHIDRA_MAX_HEAP_MB` | JVM max heap for the Ghidra subprocess, in MB. Raise to 6144-8192 for multi-MB binaries | 4096 |
| `GHIDRA_FUNCTION_TIMEOUT` | Per-function decompilation timeout in seconds | 30 |
| `GHIDRA_MAX_FUNCTIONS` | Cap on functions processed per run (0 = unlimited) | 0 |
| `GHIDRA_SKIP_DECOMPILE` | Structural pass only, no decompilation | Off |
| `GHIDRA_ENABLE_FID` | Enable Function ID library matching during analysis | Off |
| `X64DBG_HOST` | Host the Obsidian plugin's HTTP listener is on. A non-loopback host additionally requires `BINARY_MCP_REMOTE_ALLOW`, `X64DBG_TLS_CA` and `OBSIDIAN_AUTH_TOKEN` | `127.0.0.1` |
| `X64DBG_PORT` | Port that listener is on, matching what `obsidian_server.exe` binds | 8765 |
| `X64DBG_TIMEOUT` | Timeout for a single x64dbg command, in seconds | 30 |
| `X64DBG_TLS_CA` | PEM CA bundle that signs the debugger host's certificate. Setting it selects `https`. Required off loopback | Unset |
| `X64DBG_TLS_CLIENT_CERT` | PEM client certificate to present to the debugger host, for mutual TLS. Requires `X64DBG_TLS_CA` | Unset |
| `X64DBG_TLS_CLIENT_KEY` | PEM private key for that certificate | Unset |
| `OBSIDIAN_AUTH_TOKEN` | Bearer token for the plugin's API. Optional on loopback (the bridge reads the plugin's `%TEMP%` token file); **required** off loopback | Unset |
| `WINDBG_PATH` | WinDbg/CDB installation path | Auto-detected |
| `WINDBG_TIMEOUT` | Timeout for a single WinDbg command, in seconds | 30 |
| `WINDBG_DEBUG` | Verbose dbgeng diagnostics | Off |
| `KDNET_TIMEOUT` | Timeout for establishing a KDNET kernel connection, in seconds | 60 |

## Storage and scheduling

| Variable | Description | Default |
|----------|-------------|---------|
| `BINARY_CACHE_DIR` | Cache root for Ghidra projects and carved output | `~/ghidra_mcp_cache` |
| `BINARY_MCP_CARVE_DIR` | Destination for carved embedded binaries | `~/.cache/binary_mcp/carved` (POSIX), `~/.binary_mcp_cache/carved` (Windows) |
| `BINARY_MCP_SESSION_DIR` | Directory for saved analysis sessions | `~/.binary_mcp_sessions` |
| `BINARY_MCP_INLINE_DEADLINE` | Seconds a Ghidra-invoking tool blocks before handing back a job handle (max 900). Raise it if your client is patient | 25 |

Under Claude Code, long calls move to a background task after two minutes, so
90-120 returns more answers inline. See [Background jobs](jobs.md).

## Symbols

| Variable | Description | Default |
|----------|-------------|---------|
| `BINARY_MCP_AUTO_PDB` | Fetch a PDB on first import: `microsoft`, `always` or `never` | `microsoft` |
| `BINARY_MCP_SYMBOL_SERVER` | Upstream symbol server | `https://msdl.microsoft.com/download/symbols` |
| `BINARY_MCP_SYMBOL_CACHE` | On-disk symbol cache directory | `~/.cache/binary_mcp/symbols` (POSIX) |
| `BINARY_MCP_SYMBOL_PATH` | Windows-style `_NT_SYMBOL_PATH`, overrides `_NT_SYMBOL_PATH` | Unset |
| `BINARY_MCP_SYMBOL_OFFLINE` | Serve symbols only from the local cache | Off |
| `BINARY_MCP_ALLOW_HTTP_SYMBOLS` | Permit `http://` symbol servers. PDBs are MITM-sensitive | Off |
| `BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS` | Permit a symbol server on a private or loopback address, for an internal symbol store | Off |

A fetch discloses the PDB name and GUID to the server. See [Security
model](security.md#symbol-fetches-leave-the-host).

## Confinement

These are the controls described in the [security model](security.md#file-access-is-confined-by-default).

| Variable | Description | Default |
|----------|-------------|---------|
| `BINARY_MCP_ALLOWED_DIRS` | Directories analysis is confined to, separated by `:` (POSIX) or `;` (Windows) | Unset, falls back to the quarantine directories |
| `BINARY_MCP_REQUIRE_CONFINEMENT` | Fail closed: refuse to open any binary unless `BINARY_MCP_ALLOWED_DIRS` is set explicitly | Off |
| `BINARY_MCP_ALLOW_ANY_PATH` | Opt out of path confinement entirely. Not recommended: every file this process can read becomes reachable through the server. Warns once per process, and is ignored when `BINARY_MCP_REQUIRE_CONFINEMENT` is set | Off |
| `BINARY_MCP_ALLOW_HARDLINKS` | Re-permit multiply linked regular files. Narrower than `BINARY_MCP_ALLOW_ANY_PATH`: directory confinement stays in force | Off |
| `BINARY_MCP_ENABLE_RAW_WINDBG` | Enable `windbg_execute_command` behind its fail-closed allowlist | Off |

## Transport

`stdio` is the default and needs none of these: the client spawns the server
itself. Set `BINARY_MCP_TRANSPORT=http` when the client is on a different host.
See [Remote access](remote-access.md) for the full setup and
[Security model](security.md#the-http-transport) for what the listener exposes.

| Variable | Description | Default |
|----------|-------------|---------|
| `BINARY_MCP_TRANSPORT` | `stdio` or `http` | `stdio` |
| `BINARY_MCP_HTTP_HOST` | Address the HTTP transport binds. A non-loopback address additionally requires `BINARY_MCP_REMOTE_ALLOW`, TLS and an explicit token | `127.0.0.1` |
| `BINARY_MCP_HTTP_PORT` | Port the HTTP transport binds | 8770 |
| `BINARY_MCP_HTTP_PATH` | URL path the MCP endpoint is served at | `/mcp` |
| `BINARY_MCP_HTTP_TOKEN` | Bearer token the transport requires. Generated and logged once per start when unset on loopback; **required** for a non-loopback bind | Generated |
| `BINARY_MCP_HTTP_ALLOWED_HOSTS` | Extra `Host`/`Origin` values to accept, comma-separated. Add the DNS name clients dial | Bind address only |
| `BINARY_MCP_REMOTE_ALLOW` | Master switch for binding off loopback | Off |
| `BINARY_MCP_REMOTE_TLS_CERT` | PEM certificate chain. Required off loopback | Unset |
| `BINARY_MCP_REMOTE_TLS_KEY` | PEM private key for that certificate | Unset |
| `BINARY_MCP_REMOTE_TLS_CA` | PEM CA bundle for verifying client certificates. Setting it turns on mutual TLS | Unset |
| `BINARY_MCP_REMOTE_CLIENT_ALLOWLIST` | Client addresses or CIDRs allowed to connect, comma-separated. Checked before authentication | Unset, any address may present a token |

## External services

| Variable | Description | Default |
|----------|-------------|---------|
| `VT_API_KEY` | VirusTotal API key, lookups only | Unset, VT tools report how to configure it |

## Optional dependencies

```bash
uv sync --extra windbg    # Pybag, for kernel debugging (Windows only)
uv sync --extra dev       # pytest, ruff
```

Fuzzy hashing (`ssdeep`, `python-tlsh`) wraps native libraries with packaging
quirks, so it is deliberately not a project extra. Install it yourself if you
want it:

```bash
pip install ssdeep python-tlsh    # may need: apt install libfuzzy-dev
```

`compute_similarity_hashes` detects their absence and notes it in the output.
Every other similarity hash works without them.

## Jython for Ghidra 12.1+

Jython is no longer bundled with Ghidra and analysis needs it. Install it once
from the Ghidra Front End (**File -> Install Extensions -> Jython**), then
restart Ghidra. Ghidra 12.0.x and earlier ship with it and need no extra setup.
