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
| `GHIDRA_TIMEOUT` | Analysis timeout in seconds (30-3600) | 1800 |
| `GHIDRA_MAX_HEAP_MB` | JVM max heap for the Ghidra subprocess, in MB. Raise to 6144-8192 for multi-MB binaries | 4096 |
| `GHIDRA_FUNCTION_TIMEOUT` | Per-function decompilation timeout in seconds | 30 |
| `GHIDRA_MAX_FUNCTIONS` | Cap on functions processed per run (0 = unlimited) | 0 |
| `GHIDRA_SKIP_DECOMPILE` | Structural pass only, no decompilation | Off |
| `GHIDRA_ENABLE_FID` | Enable Function ID library matching during analysis | Off |
| `X64DBG_BRIDGE_URL` | x64dbg HTTP bridge URL | `http://localhost:27042` |
| `X64DBG_TIMEOUT` | Timeout for a single x64dbg command, in seconds | 30 |
| `WINDBG_PATH` | WinDbg/CDB installation path | Auto-detected |
| `WINDBG_TIMEOUT` | Timeout for a single WinDbg command, in seconds | 30 |

## Storage and scheduling

| Variable | Description | Default |
|----------|-------------|---------|
| `BINARY_CACHE_DIR` | Cache root for Ghidra projects and carved output | `~/ghidra_mcp_cache` |
| `BINARY_MCP_CARVE_DIR` | Destination for carved embedded binaries | `~/.cache/binary_mcp/carved` (POSIX), `~/.binary_mcp_cache/carved` (Windows) |
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

A fetch discloses the PDB name and GUID to the server. See [Security
model](security.md#symbol-fetches-leave-the-host).

## Confinement

These are the controls described in the [security model](security.md#file-access-is-confined-by-default).

| Variable | Description | Default |
|----------|-------------|---------|
| `BINARY_MCP_ALLOWED_DIRS` | Directories analysis is confined to, separated by `:` (POSIX) or `;` (Windows) | Unset, falls back to the quarantine directories |
| `BINARY_MCP_REQUIRE_CONFINEMENT` | Fail closed: refuse to open any binary unless `BINARY_MCP_ALLOWED_DIRS` is set explicitly | Off |
| `BINARY_MCP_ALLOW_ANY_PATH` | Opt out of path confinement entirely. Not recommended: every file this process can read becomes reachable through the server. Warns once per process, and is ignored when `BINARY_MCP_REQUIRE_CONFINEMENT` is set | Off |
| `BINARY_MCP_ENABLE_RAW_WINDBG` | Enable `windbg_execute_command` behind its fail-closed allowlist | Off |

## External services

| Variable | Description | Default |
|----------|-------------|---------|
| `VT_API_KEY` | VirusTotal API key, lookups only | Unset, VT tools report how to configure it |
| `VT_API_TIMEOUT` | Socket timeout for VirusTotal calls, in seconds (clamped 5-300) | 30 |
| `ABUSECH_API_KEY` | abuse.ch Auth-Key. One key covers MalwareBazaar, ThreatFox, URLhaus and YARAify, and is mandatory for all of them since 30 June 2025. Free from <https://auth.abuse.ch/> | Unset, the tools report how to configure it |
| `MB_API_KEY` | Alias for `ABUSECH_API_KEY`, kept because it shipped first. `ABUSECH_API_KEY` wins if both are set | Unset |
| `MB_API_TIMEOUT` | Socket timeout for MalwareBazaar calls, in seconds (clamped 5-300) | 30 |
| `ABUSECH_API_TIMEOUT` | Socket timeout for ThreatFox/URLhaus/YARAify calls, in seconds (clamped 5-300) | 30 |
| `MB_ALLOW_DOWNLOAD` | Enable `mb_download`, the only tool that writes a sample to disk. Archives are saved encrypted under `~/.binary_mcp_output/malwarebazaar/` and never extracted | Unset (off) |
| `MB_MAX_DOWNLOAD_MB` | Ceiling on a downloaded archive, in MB (clamped 1-2048) | 128 |
| `ATTACK_DOMAIN` | ATT&CK matrix: `enterprise-attack`, `mobile-attack` or `ics-attack` | `enterprise-attack` |
| `ATTACK_DATA_DIR` | Where the distilled ATT&CK index is cached | `$BINARY_CACHE_DIR/attack` |
| `ATTACK_OFFLINE` | Refuse to download ATT&CK data, serve only what is already cached | Unset (off) |
| `ATTACK_MAX_BUNDLE_MB` | Ceiling on the downloaded STIX bundle, in MB (clamped 8-1024). Enterprise is ~51MB today | 128 |
| `ATTACK_TIMEOUT` | Socket timeout for the ATT&CK download, in seconds (clamped 5-600) | 120 |

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
