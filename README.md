# Binary MCP Server

[![CI](https://github.com/sarks0/binary-mcp/workflows/CI/badge.svg)](https://github.com/sarks0/binary-mcp/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

MCP server that gives AI assistants the ability to analyze binaries, debug processes, and inspect kernel state. Supports static analysis via Ghidra, user-mode debugging via x64dbg, kernel debugging via WinDbg, and .NET decompilation via ILSpyCmd.

## Quick Start

### Install

```bash
# Windows (as Administrator)
irm https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.ps1 | iex

# Linux / macOS
curl -sSL https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.py | python3 -

# Manual
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp && uv sync
```

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

**Static Analysis** -- Analyze any binary without running it.
```
Analyze the binary at /path/to/malware.exe
Decompile the function at 0x401000
Find all suspicious API calls and crypto constants
```

**Live Debugging** -- Control x64dbg from Claude.
```
Connect to x64dbg and set breakpoints on BCryptEncrypt
Trace execution until EAX contains a decrypted pointer
Find the OEP of this packed binary
```

**Kernel Debugging** -- Inspect drivers and crash dumps.
```
Connect to the kernel debugger on port 50000
Show the dispatch table for \\Driver\\MyDriver
Analyze the crash dump at C:\Windows\MEMORY.DMP
```

**.NET Analysis** -- Decompile managed assemblies.
```
Decompile the type MyNamespace.MyClass to C#
```

## Capabilities

### Static Analysis (Ghidra) -- 35 tools

Analysis, decompilation, cross-references, memory maps, byte pattern search, function renaming, call graphs, API pattern detection (100+ Windows APIs), crypto constant identification, IOC extraction, and binary compatibility checking.

### Dynamic Analysis (x64dbg) -- 150+ tools

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

### Kernel Debugging (WinDbg) -- 20 tools

Connection (KDNET, local kernel, crash dumps), execution control, breakpoints, register and memory inspection, driver object analysis, IOCTL decoding, process listing, and raw WinDbg command execution.

### .NET Analysis (ILSpyCmd) -- 7 tools

Type listing, C# decompilation, IL disassembly, type search, and full assembly decompilation.

### Other

- **Session Management** -- Persistent analysis tracking across conversations
- **Triage** -- Quick file type detection, packer identification, entropy analysis
- **YARA** -- Rule scanning (optional `yara-python` dependency)
- **Malware Analysis** -- Behavior detection, threat chain identification, IOC extraction
- **Reporting** -- Generate structured analysis reports

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

Apache 2.0 -- See [LICENSE](LICENSE) for details.
