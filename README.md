# Binary MCP Server

[![CI](https://github.com/sarks0/binary-mcp/workflows/CI/badge.svg)](https://github.com/sarks0/binary-mcp/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

MCP server that gives AI assistants the ability to analyze binaries, debug processes, and inspect kernel state. Supports static analysis via Ghidra, user-mode debugging via x64dbg, kernel debugging via WinDbg, and .NET decompilation via ILSpyCmd.

## Quick Start

### Install

Clone, or download the installer and read it before running it. The installers
pull down Ghidra, x64dbg, the Windows debuggers and this project's own x64dbg
plugins, and `install.ps1` requires Administrator.

```bash
# Recommended: clone, then run the installer from the checkout
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp
python3 install.py          # Windows: .\install.ps1  (as Administrator)

# Or just the dependencies, no installer
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp && uv sync
```

Without git — download, check what you got, look at it, then run it:

```bash
# Linux / macOS
curl -fsSLO https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.py
sha256sum install.py
less install.py
python3 install.py
```

```powershell
# Windows (as Administrator)
Invoke-WebRequest -Uri https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.ps1 -OutFile install.ps1
Get-FileHash .\install.ps1 -Algorithm SHA256
notepad .\install.ps1
.\install.ps1
```

> **No `| iex` / `| python3 -` one-liner is offered on purpose.** Piping a fresh
> download into an interpreter runs whatever the network returned, with no copy
> on disk to inspect, nothing to compare a digest against, and no record of what
> ran — and on Windows it runs elevated. The extra command above is the whole
> difference. See [INSTALL.md → Supply-Chain
> Integrity](INSTALL.md#supply-chain-integrity) for what the installers verify
> and how to pin a digest.

### Connect to Claude

```bash
claude mcp add binary-analysis -- uv --directory /path/to/binary-mcp run python -m src.server
```

Or add to your MCP config (Claude Code `~/.claude/settings.json` or Claude Desktop config):

```json
{
  "mcpServers": {
    "binary-analysis": {
      "command": "uv",
      "args": ["--directory", "/path/to/binary-mcp", "run", "python", "-m", "src.server"],
      "env": {"GHIDRA_HOME": "/path/to/ghidra"}
    }
  }
}
```

## What You Can Do

**Static Analysis** - Analyze any binary without running it.
```
Analyze the binary at /path/to/malware.exe
Decompile the function at 0x401000
Find all suspicious API calls and crypto constants
```

**Live Debugging** - Control x64dbg from Claude.
```
Connect to x64dbg and set breakpoints on BCryptEncrypt
Trace execution until EAX contains a decrypted pointer
Find the OEP of this packed binary
```

**Kernel Debugging** - Inspect drivers and crash dumps.
```
Connect to the kernel debugger on port 50000
Show the dispatch table for \\Driver\\MyDriver
Analyze the crash dump at C:\Windows\MEMORY.DMP
```

**.NET Analysis** - Decompile managed assemblies.
```
Decompile the type MyNamespace.MyClass to C#
```

## Capabilities (279 tools)

Counts below are derived from the tools actually registered by `src/server.py`, and `tests/test_docs_accuracy.py` fails if this file and the code disagree.

### Static Analysis (Ghidra) - 19 tools

Analysis, decompilation, cross-references, memory maps, byte pattern search, function renaming, call graphs, API pattern detection (100+ Windows APIs), crypto constant identification, IOC extraction, PDB loading, and binary compatibility checking.

### Python & Encoding Utilities - 7 tools

Python bytecode (`.pyc`) analysis, PyInstaller/py2exe packer detection and extraction, packed-archive listing, XOR key recovery and decryption, and Base64 file decoding.

### Sessions & Server Utilities - 15 tools

Persistent analysis sessions (create, save, load, list, delete, summarise, relate), analyst notes, auto-session configuration, cache cleanup, and a setup diagnostic.

### Dynamic Analysis (x64dbg) - 159 tools

| Category | What It Does |
|----------|-------------|
| **Execution Control** | Run, pause, step into/over/out, run to user code, instruction undo |
| **Breakpoints** | Software, hardware, memory, DLL load, exception, and conditional breakpoints with logging |
| **Tracing** | Conditional tracing (ticnd/tocnd), trace recording, OEP finder for packed binaries |
| **Memory** | Read, write, dump, allocate, protect, pattern scan, string search, memory watch with diff |
| **Registers & Stack** | Read/write registers, stack trace with raw fallback, expression evaluation |
| **Analysis** | Control flow analysis, cross-references, function boundaries, disassembly with capstone fallback |
| **Type System** | Define structs/unions, overlay on memory (VisitType), parse C headers, enumerate types |
| **Search** | Find assembly patterns, GUIDs, module calls, string references, reference ranges |
| **Anti-Debug** | Detect and bypass anti-debug techniques (PEB, NtGlobalFlag, heap flags) |
| **Watch & Logging** | Watch expressions with watchdog triggers, API call logging, breakpoint hit logging |
| **Annotations** | Comments, labels, bookmarks, function boundaries, variables |
| **Thread Control** | Switch, suspend, resume threads individually or all at once |
| **Process** | Attach/detach, minidump creation, module listing with exports |
| **Navigation** | Navigate disassembly/dump/graph views, generic command execution |

### Kernel Debugging (WinDbg) - 33 tools

Connection (KDNET, named pipe, serial, local kernel, crash dumps), execution control, software/hardware/conditional breakpoints, register, memory and thread inspection, structure display (`dt`), disassembly, module and process listing, symbol path management, and raw WinDbg command execution. Windows only - every tool returns a platform message elsewhere.

### .NET Analysis (ILSpyCmd) - 7 tools

Type listing, C# decompilation, IL disassembly, type search, full assembly decompilation, and a setup diagnostic.

### PE Structure (pefile) - 4 tools

Comprehensive PE header, section, import, export, resource, debug, TLS, and Rich header analysis in a single call, at three detail levels (basic/standard/full) with decoded characteristic flags, compiler attribution, and malware indicators. Plus Authenticode signature inspection, embedded-binary carving, and similarity hashing.

### Other - 35 tools

- **Triage (3)** - Quick file type detection, packer identification, entropy analysis
- **Malware Analysis (6)** - Behavior detection, API call chains, dynamic API resolution, anti-analysis detection, stack-string recovery, IOC extraction with context
- **Control Flow (4)** - CFG generation, cyclomatic complexity, loop detection, dead code
- **Function Hashing (5)** - Cross-binary function matching, similarity scoring, inlined-clone detection, batch decompilation, completeness checks
- **Pseudocode Review (5)** - Decompiler-output scanning, caller analysis, parameter sinks, switch tables, review packages
- **VirusTotal (4)** - Hash lookups, sandbox behavior reports, Intelligence search, API-key check. Read-only: see "Operational safety" below
- **Reporting (2)** - Generate structured analysis reports, export IOCs
- **YARA (2)** - Rule *generation* from session data or extracted strings. This server emits rule text; it does not compile or run rules, so no YARA library is required or installed
- **IOCTL Dispatch (1)** - Recover driver IOCTL handlers
- **Binary Diff (1)** - Cross-binary patch diffing
- **Indirect Calls (1)** - Vtable enumeration
- **Function ID (1)** - Ghidra FID library-match reading

## Operational safety

This is a malware-analysis tool. Analyze samples in an isolated VM, on a
host you can revert. That advice is partly enforced by the code, and it is
worth being precise about which parts:

- **No tool can execute a sample.** Nothing in `src/tools/` starts a process
  from a file on disk. The x64dbg bridge has a `load_binary()` method and the
  C++ plugin has a `LOAD_BINARY` handler, but no MCP tool calls either, so
  neither is reachable from a client. `x64dbg_attach` attaches to a PID that
  is *already running* - you decide what runs, and where.
- **Raw debugger commands are filtered, not sandboxed.**
  `x64dbg_execute_command` is gated by an allowlist at the tool layer and a
  second, authoritative allowlist in the C++ plugin, which fails closed on any
  command name it does not recognise. Only the command's first token is
  checked; its arguments are forwarded verbatim.
  `windbg_execute_command` is gated by a token-aware *denylist* that splits
  compound commands, recurses into nested bodies, and refuses process control,
  host file I/O, script and command-file execution, module loading, symbol-path
  changes, and target memory/register writes - a handful of argument forms
  (`r @rip = ...`, `.process /i`, `!chkimg /f`, `s -b`) are matched too.
  Anything not named still reaches the debugger. Both tools act on a live
  target with the debugger's full read access. See each tool's docstring for
  the exact rules.
- **Samples are never uploaded anywhere.** The VirusTotal integration performs
  GET lookups only - hash reports, behavior summaries, and Intelligence
  search. There is no submission or upload tool, so no sample can leave your
  host through it, deliberately or by accident. Sending a hash still tells
  VirusTotal you have the sample; sending the file would tell everyone with VT
  Intelligence access.
- **File access is confined by default.** Binary paths go through
  `sanitize_binary_path` (`src/utils/security.py`), which checks a symlink's
  target for containment before following it, and answers "denied" identically
  whether or not the path exists so it cannot be used to probe the filesystem.
  With `BINARY_MCP_ALLOWED_DIRS` unset, access defaults to a quarantine allow-list -
  the system temp directory, this server's cache root (`$BINARY_CACHE_DIR` or
  `~/ghidra_mcp_cache`), and `~/.binary_mcp_cache` / `~/.cache/binary_mcp` -
  so `~/.ssh/id_rsa` and `/etc/shadow` are out of reach without you saying so.
  Report and rule output is separately confined to `~/.binary_mcp_output/`.

## Supported Formats

| Format | Engine |
|--------|--------|
| PE (.exe, .dll, .sys) | Ghidra + x64dbg |
| .NET Assembly | ILSpyCmd |
| ELF (Linux) | Ghidra |
| Mach-O (macOS) | Ghidra |
| Kernel Drivers (.sys) | Ghidra + WinDbg |
| Crash Dumps (.dmp) | WinDbg |

## Architecture

```
                    MCP Client (Claude Desktop / Claude Code)
                                    |
                            FastMCP Server (stdio)
                           /        |        \         \
                  Static Analysis  Dynamic    Kernel    .NET
                   /       \       Analysis  Debugging  Analysis
               Ghidra    Python   x64dbg     WinDbg/KD  ILSpyCmd
             (headless)  bytecode (HTTP)    (Pybag COM)
                                    |           |
                               C++ Plugin   DbgEng COM
                                    |           |
                              User Process  Kernel Target
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GHIDRA_HOME` | Ghidra installation path | Auto-detected |
| `GHIDRA_TIMEOUT` | Analysis timeout (seconds) | 600 |
| `X64DBG_PATH` | x64dbg installation path | Auto-detected |
| `WINDBG_PATH` | WinDbg/CDB installation path | Auto-detected |
| `WINDBG_MODE` | Operating mode: `kernel`, `user`, `dump` | `kernel` |
| `BINARY_CACHE_DIR` | Cache root for Ghidra projects and carved output | `~/ghidra_mcp_cache` |
| `VT_API_KEY` | VirusTotal API key (lookups only) | Unset - VT tools report how to configure it |
| `BINARY_MCP_ALLOWED_DIRS` | Directories analysis is confined to, separated by `:` (POSIX) or `;` (Windows) | Unset - falls back to the quarantine directories described under "Operational safety" |
| `BINARY_MCP_REQUIRE_CONFINEMENT` | Fail closed: refuse to open any binary unless `BINARY_MCP_ALLOWED_DIRS` is set explicitly | Unset (off) |
| `BINARY_MCP_ALLOW_ANY_PATH` | Opt out of path confinement entirely. Not recommended - every file this process can read becomes reachable through the server. Logs a warning once per process, and is ignored when `BINARY_MCP_REQUIRE_CONFINEMENT` is set | Unset (off) |

**Ghidra 12.1+ users:** Jython is no longer bundled with Ghidra and is required for analysis. Install it once from the Ghidra Front End: **File -> Install Extensions -> Jython**, then restart Ghidra. Ghidra 12.0.x and earlier ship with Jython built in and need no extra setup.

## Development

```bash
uv run pytest              # Run tests
uv run pytest --cov=src    # With coverage
uv run ruff check src/     # Lint
```

## Resources

- [Installation Guide](INSTALL.md)
- [Contributing](CONTRIBUTING.md)
- [WinDbg/Kernel Debugging Guide](docs/windbg-kernel-debugging.md)
- [x64dbg Architecture](docs/x64dbg-architecture.md)
- [MCP Protocol](https://modelcontextprotocol.io/)

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
