# Binary MCP Server

[![CI](https://github.com/sarks0/binary-mcp/workflows/CI/badge.svg)](https://github.com/sarks0/binary-mcp/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

MCP server providing AI assistants with comprehensive binary analysis capabilities. Combines static analysis (Ghidra, ILSpyCmd), user-mode debugging (x64dbg), and kernel-level debugging (WinDbg) into a unified interface for security research, reverse engineering, and vulnerability discovery.

## Features

- **Static Analysis**: Native binaries (Ghidra) and .NET assemblies (ILSpyCmd)
- **User-Mode Debugging**: x64dbg integration with breakpoints, tracing, and memory inspection
- **Kernel Debugging**: WinDbg/KD via Pybag COM API for driver analysis, IOCTL research, and crash dump analysis
- **Smart Caching**: SHA256-based caching for 30-120x speed improvement on re-analysis
- **Session Management**: Persistent analysis tracking across conversations with auto-resume
- **Pattern Detection**: 100+ Windows API patterns and crypto constants
- **Structured Errors**: 50+ error codes with actionable suggestions for resolution

## Quick Start

### Windows

```powershell
# Run interactive installer (as Administrator)
irm https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.ps1 | iex
```

Auto-installs: Python, Java, .NET, Ghidra, x64dbg, and configures Claude.

For WinDbg/kernel debugging support:

```powershell
pip install binary-mcp[windbg]
```

Requires [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) (includes `cdb.exe` and `kd.exe`). For full local kernel access, enable debug mode as Administrator: `bcdedit -debug on` then reboot (see [Troubleshooting](#troubleshooting)).

### Linux / macOS

```bash
# Run interactive installer
curl -sSL https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.py | python3 -
```

Auto-installs prerequisites via package manager (apt/dnf/brew/pacman).

> **Note**: WinDbg/kernel debugging tools are Windows-only. Static analysis and x64dbg remote debugging work on all platforms.

### Manual Installation

```bash
# Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and install
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp
uv sync

# Optional: WinDbg support (Windows only)
uv sync --extra windbg
```

## Configuration

### Claude Code

Add the MCP server directly from the command line:

```bash
claude mcp add binary-analysis -- uv --directory /absolute/path/to/binary-mcp run python -m src.server
```

Or manually edit `~/.claude/settings.json` (global) or `.claude/settings.json` (per-project):

```json
{
  "mcpServers": {
    "binary-analysis": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/binary-mcp", "run", "python", "-m", "src.server"],
      "env": {"GHIDRA_HOME": "/path/to/ghidra"}
    }
  }
}
```

### Claude Desktop

Edit the Claude Desktop config file:

| Platform | Config path |
|----------|-------------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "binary-analysis": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/binary-mcp", "run", "python", "-m", "src.server"],
      "env": {"GHIDRA_HOME": "/path/to/ghidra"}
    }
  }
}
```

Restart Claude Desktop after saving.

## Usage

**Static Analysis:**
```
Analyze the binary at /path/to/sample.exe
Show me all functions in the binary
Decompile the function at address 0x401000
Find all suspicious Windows API calls
```

**.NET Analysis:**
```
Analyze the .NET assembly at /path/to/app.exe
Decompile the type MyNamespace.MyClass
```

**User-Mode Debugging (x64dbg):**
```
Connect to x64dbg and set a breakpoint at 0x401000
Step through the function and show me the registers
```

**Kernel Debugging (WinDbg):**
```
Connect to the kernel debugger on port 50000
Show me the dispatch table for \\Driver\\MyDriver
Decode IOCTL code 0x9C402408
Analyze the crash dump at C:\Windows\MEMORY.DMP
List all loaded kernel drivers
```

## Available Tools

### Static Analysis (27 tools)

**Core (Ghidra):**
- `analyze_binary` - Run Ghidra analysis
- `check_binary` - Check binary compatibility
- `get_functions` - List functions
- `get_imports` - Extract imports
- `get_strings` - Extract strings
- `decompile_function` - Decompile to pseudocode
- `get_xrefs` - Get cross-references

**Pattern Detection:**
- `find_api_calls` - Identify Windows API usage
- `detect_crypto` - Find crypto constants
- `generate_iocs` - Extract IPs, domains, URLs

**Advanced:**
- `get_call_graph` - Function call graphs
- `get_memory_map` - Memory layout
- `search_bytes` - Byte pattern search
- `rename_function` - Rename functions in cache

**.NET (7 tools):**
- `analyze_dotnet` - List assembly types
- `get_dotnet_types` - Filter types
- `decompile_dotnet_type` - Decompile to C#
- `decompile_dotnet_assembly` - Full decompilation
- `search_dotnet_types` - Search by pattern
- `get_dotnet_il` - IL disassembly

### Dynamic Analysis - x64dbg (14 tools)

- `x64dbg_connect`, `x64dbg_status`, `x64dbg_run`, `x64dbg_pause`
- `x64dbg_step_into`, `x64dbg_step_over`
- `x64dbg_set_breakpoint`, `x64dbg_delete_breakpoint`, `x64dbg_list_breakpoints`
- `x64dbg_get_registers`, `x64dbg_read_memory`, `x64dbg_disassemble`
- `x64dbg_trace_execution`, `x64dbg_run_to_address`

### Kernel Debugging - WinDbg (20 tools)

**Connection:**
- `windbg_connect_kernel` - Connect via KDNET (port + key)
- `windbg_open_dump` - Open crash dump (.dmp)
- `windbg_disconnect` - Disconnect from target
- `windbg_status` - Debugger status summary

**Execution Control:**
- `windbg_run`, `windbg_pause`, `windbg_step_into`, `windbg_step_over`
- `windbg_run_and_wait` - Run until breakpoint
- `windbg_wait_paused` - Wait for break-in

**Breakpoints:**
- `windbg_set_breakpoint` - Set breakpoint (address or symbol)
- `windbg_delete_breakpoint` - Remove breakpoint
- `windbg_list_breakpoints` - List all breakpoints
- `windbg_set_conditional_breakpoint` - Conditional breakpoint with command

**Inspection:**
- `windbg_get_registers` - Read all registers
- `windbg_read_memory` - Read memory at address
- `windbg_write_memory` - Write memory
- `windbg_disassemble` - Disassemble at address
- `windbg_get_modules` - List loaded modules/drivers
- `windbg_execute_command` - Execute raw WinDbg command

### Session Management (7 tools)

- `start_analysis_session` - Begin tracking
- `save_session` - Persist data
- `list_sessions` - List all sessions
- `load_session_section` - Load specific outputs
- `delete_session` - Clean up

## Supported Formats

| Format | Engine | Status |
|--------|--------|--------|
| PE (.exe, .dll, .sys) | Ghidra | Full |
| .NET Assembly | ILSpyCmd | Full |
| ELF (Linux) | Ghidra | Full |
| Mach-O (macOS) | Ghidra | Full |
| Kernel Drivers (.sys) | Ghidra + WinDbg | Full |
| Crash Dumps (.dmp) | WinDbg | Full |
| Raw Binary | Ghidra | Limited |

## Architecture

```
                    MCP Client (Claude Desktop / Claude Code)
                                    |
                            FastMCP Server (stdio)
                           /        |        \
                Static Analysis  Dynamic Analysis  Kernel Debugging
                  /       \         |                    |
              Ghidra   ILSpyCmd   x64dbg             WinDbg/KD
            (headless)  (.NET)   (HTTP bridge)    (Pybag COM API)
                                     |                   |
                                 C++ Plugin         DbgEng COM
                                     |                   |
                                User Process      Kernel Target
```

## Troubleshooting

**Ghidra not found:**
```bash
export GHIDRA_HOME=/path/to/ghidra
diagnose_setup
```

**ILSpyCmd not found:**
```bash
dotnet tool install -g ilspycmd
diagnose_dotnet_setup
```

**WinDbg not found:**
```powershell
# Install Windows SDK (includes Debugging Tools)
# Or set path manually:
set WINDBG_PATH=C:\Program Files (x86)\Windows Kits\10\Debuggers\x64
```

**Kernel debugging setup:**

Local kernel debugging requires enabling debug mode and rebooting:

```powershell
# Run as Administrator:
bcdedit -debug on
shutdown /r /t 0
```

> **Secure Boot**: If `bcdedit -debug on` fails with an error, Secure Boot is likely enabled.
> Disable it in BIOS/UEFI settings (Security → Secure Boot → Disabled), then retry.
> After enabling debug mode and rebooting, run the MCP server as Administrator.

Without `bcdedit -debug on`, local kernel access is limited — symbol lookups (`x`, `dt`, `u`, `lm`) work via KD, but registers, memory reads, `!process`, and call stacks will fail.

**KDNET remote kernel debugging:**
```powershell
# On target machine (enable KDNET):
bcdedit /debug on
bcdedit /dbgsettings net hostip:<HOST_IP> port:50000 key:1.2.3.4

# Then in Claude:
# "Connect to kernel debugger on port 50000 with key 1.2.3.4"
```

**Analysis timeout:**
```bash
export GHIDRA_TIMEOUT=1200
```

## Development

```bash
# Run tests
uv run pytest

# With coverage
uv run pytest --cov=src

# Lint
make lint

# Format
make format
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GHIDRA_HOME` | Ghidra installation path | Auto-detected |
| `GHIDRA_PROJECT_DIR` | Project directory | `~/.ghidra_projects` |
| `GHIDRA_TIMEOUT` | Analysis timeout (seconds) | 600 |
| `X64DBG_PATH` | x64dbg executable path | Auto-detected |
| `WINDBG_PATH` | WinDbg/CDB installation path | Auto-detected from Windows SDK |
| `WINDBG_MODE` | Operating mode: `kernel`, `user`, `dump` | `kernel` |
| `WINDBG_SYMBOL_PATH` | Symbol server path | Microsoft public symbols |
| `WINDBG_TIMEOUT` | Command timeout (seconds) | 30 |

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Resources

- **Documentation**: [docs/](docs/)
- **WinDbg/Kernel Debugging Guide**: [docs/windbg-kernel-debugging.md](docs/windbg-kernel-debugging.md)
- **Issues**: [github.com/Sarks0/binary-mcp/issues](https://github.com/Sarks0/binary-mcp/issues)
- **MCP Protocol**: [modelcontextprotocol.io](https://modelcontextprotocol.io/)

## License

Apache 2.0 - See LICENSE file for details.
