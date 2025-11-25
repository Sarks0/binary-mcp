# Binary MCP Server

[![CI](https://github.com/sarks0/binary-mcp/workflows/CI/badge.svg)](https://github.com/sarks0/binary-mcp/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Model Context Protocol (MCP) server that provides AI assistants with comprehensive binary analysis capabilities. Supports native binaries via Ghidra, .NET assemblies via ILSpyCmd, and dynamic analysis via x64dbg. Built for security research, malware analysis, and reverse engineering.

## Features

- **Native Binary Analysis**: Ghidra integration with decompilation, function extraction, and pattern detection
- **.NET Assembly Analysis**: ILSpyCmd integration for C# decompilation (cross-platform)
- **Dynamic Analysis**: x64dbg debugging with breakpoints, memory inspection, and execution tracing
- **Binary Compatibility Checker**: Auto-detects format and recommends appropriate tools
- **Intelligent Caching**: SHA256-based caching for fast repeated queries
- **Session System**: Incremental analysis storage with compression for large binaries
- **Malware Detection**: 100+ Windows API patterns and cryptographic constant detection

## Quick Start

### Windows (Recommended)

The easiest way to install on Windows is using the interactive installer:

```powershell
# Run as Administrator
irm https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.ps1 | iex
```

Or download and run manually:
```powershell
# Download installer
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.ps1" -OutFile "install.ps1"

# Run installer (as Administrator)
.\install.ps1
```

**Installer Features:**
- Interactive menu with installation profiles (Full, Static Only, Dynamic Only, Custom)
- Auto-detects installed components
- **Automatic prerequisite installation via winget** (Python, Java, .NET SDK/Runtime, Git)
- Downloads and installs Ghidra, x64dbg, and MCP plugins
- Configures Claude Desktop and Claude Code automatically
- Unattended mode for scripted deployments: `.\install.ps1 -InstallProfile full -Unattended`

### Linux / macOS

Use the interactive Python installer:

```bash
# Download and run installer
curl -sSL https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.py | python3 -
```

Or clone and run manually:
```bash
# Clone repository
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp

# Run interactive installer
python3 install.py

# Or use unattended mode
python3 install.py --profile full --unattended
```

**Installer Features:**
- Interactive menu with installation profiles (Full, Static Only, Minimal, Custom, Repair)
- Auto-detects installed components (Python, Java, .NET, Ghidra, ILSpyCmd)
- **Automatic prerequisite installation** via package manager (apt, dnf, brew, pacman, zypper, apk)
- Downloads and installs Ghidra
- Installs ILSpyCmd for .NET analysis
- Configures Claude Desktop and Claude Code automatically
- Unattended mode for scripted deployments

**Manual installation** (if you prefer):
```bash
# Install uv (if not installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Verify installation
uv run python -m src.server
```

### Prerequisites

| Component | Required For | Windows | Linux/macOS |
|-----------|--------------|---------|-------------|
| **Python 3.12+** | Core | `winget install Python.Python.3.12` | `apt install python3` / `brew install python` |
| **Java 21+** | Ghidra | `winget install EclipseAdoptium.Temurin.21.JDK` | `apt install openjdk-21-jdk` / `brew install openjdk@21` |
| **Ghidra** | Native analysis | [ghidra-sre.org](https://ghidra-sre.org/) | [ghidra-sre.org](https://ghidra-sre.org/) |
| **.NET SDK 8.0** | .NET analysis | `winget install Microsoft.DotNet.SDK.8` | [docs.microsoft.com](https://docs.microsoft.com/dotnet/core/install/linux) / `brew install dotnet-sdk` |
| **.NET Runtime 8.0** | ILSpyCmd | `winget install Microsoft.DotNet.Runtime.8` | Included with SDK |
| **ILSpyCmd** | .NET analysis | `dotnet tool install -g ilspycmd` | `dotnet tool install -g ilspycmd` |
| **x64dbg** | Dynamic analysis | [x64dbg.com](https://x64dbg.com/) | Windows only |

> **Note:** Both installers can automatically install prerequisites via their respective package managers (winget on Windows, apt/dnf/brew/pacman on Linux/macOS).

### Configuration

Add to your MCP client config file:

**Claude Desktop:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Claude Code:**
- All platforms: `~/.config/claude-code/mcp_settings.json`

```json
{
  "mcpServers": {
    "binary-analysis": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/binary-mcp",
        "run",
        "python",
        "-m",
        "src.server"
      ],
      "env": {
        "GHIDRA_HOME": "/path/to/ghidra"
      }
    }
  }
}
```

**Important:** Replace `/absolute/path/to/binary-mcp` with your actual project path.

Restart your MCP client after configuration.

## Usage

### Basic Binary Analysis

```
Analyze the binary at /path/to/sample.exe
```

Claude will automatically:
- Check binary compatibility and format
- Run appropriate analysis (Ghidra for native, ILSpyCmd for .NET)
- Extract functions, imports, exports, and strings
- Identify suspicious API calls
- Decompile key functions

### .NET Assembly Analysis

For .NET executables (.exe/.dll compiled with C#, VB.NET, F#):

```
Analyze the .NET assembly at /path/to/malware.exe
```

Or explicitly use .NET tools:

```
# List all types in the assembly
analyze_dotnet("/path/to/sample.exe")

# Decompile a specific class to C#
decompile_dotnet_type("/path/to/sample.exe", "Namespace.ClassName")

# Search for types by pattern
search_dotnet_types("/path/to/sample.exe", "Crypto|Encrypt")
```

### Common Tasks

**List Functions:**
```
Show me all functions in the binary
```

**Decompile Function:**
```
Decompile the function at address 0x401000
```

**Find Suspicious APIs:**
```
Find all suspicious Windows API calls in the binary
```

**Extract Indicators:**
```
Extract all IOCs (IP addresses, domains, URLs) from this binary
```

**Detect Cryptography:**
```
Check if this binary uses any crypto algorithms
```

**Check Binary Format:**
```
Check what type of binary this is before analyzing
```

### Analysis Sessions

For large binaries or multi-step analysis:

```
Start an analysis session for /path/to/malware.exe with tags: ransomware, apt28
```

Sessions save all tool outputs incrementally, allowing you to:
- Continue analysis across conversations
- Load specific sections to avoid context overflow
- Recover from crashes or token limits

## Available Tools

### Static Analysis - Native (22 tools)

**Core Analysis (Ghidra):**
- `analyze_binary` - Run Ghidra headless analysis (auto-detects .NET and warns)
- `check_binary` - Check binary compatibility before analysis
- `get_functions` - List all functions with signatures
- `get_imports` - Extract imported libraries and functions
- `get_strings` - Extract strings with cross-references
- `decompile_function` - Decompile to C-like pseudocode
- `get_xrefs` - Get cross-references for addresses

**Pattern Detection:**
- `find_api_calls` - Identify Windows API usage by category
- `detect_crypto` - Find cryptographic constants (AES, MD5, SHA, RSA, RC4)
- `generate_iocs` - Extract IPs, domains, URLs, file paths, registry keys

**Advanced:**
- `get_call_graph` - Generate function call graphs
- `get_memory_map` - Extract memory layout with permissions
- `search_bytes` - Search for byte patterns
- `list_data_types` - List structures and enums
- `extract_metadata` - Get binary headers and metadata

### Static Analysis - .NET (7 tools)

**.NET Analysis (ILSpyCmd):**
- `analyze_dotnet` - Analyze .NET assembly and list all types
- `get_dotnet_types` - List types with filtering (class, interface, enum, etc.)
- `decompile_dotnet_type` - Decompile specific type to C# source code
- `search_dotnet_types` - Search types by regex pattern
- `decompile_dotnet_assembly` - Decompile entire assembly to C# files
- `get_dotnet_il` - Get IL (Intermediate Language) disassembly
- `diagnose_dotnet_setup` - Check ILSpyCmd installation status

### Dynamic Analysis (14 tools)

**x64dbg Integration** - Uses external process architecture:
- Plugin DLL (`x64dbg_mcp.dp64`) spawns HTTP server process
- Named Pipe IPC for crash isolation
- Server failures don't affect debugger
- See [ARCHITECTURE.md](src/engines/dynamic/x64dbg/ARCHITECTURE.md) for details

**Debugger Control:**
- `x64dbg_connect`, `x64dbg_status`, `x64dbg_run`, `x64dbg_pause`
- `x64dbg_step_into`, `x64dbg_step_over`

**Breakpoints:**
- `x64dbg_set_breakpoint`, `x64dbg_delete_breakpoint`, `x64dbg_list_breakpoints`

**Inspection:**
- `x64dbg_get_registers`, `x64dbg_read_memory`, `x64dbg_disassemble`

**Advanced:**
- `x64dbg_trace_execution`, `x64dbg_run_to_address`

### Session Management (7 tools)

- `start_analysis_session` - Begin tracking analysis outputs
- `save_session` - Persist session data (compressed)
- `list_sessions` - List all sessions with filters
- `get_session_summary` - Get session metadata
- `load_session_section` - Load specific tool outputs
- `load_full_session` - Load complete session
- `delete_session` - Clean up sessions

## Supported Formats

| Format | Engine | Analysis Type |
|--------|--------|---------------|
| **PE** (Windows .exe, .dll, .sys) | Ghidra | Native code decompilation |
| **.NET Assembly** (.exe, .dll) | ILSpyCmd | C# decompilation |
| **ELF** (Linux binaries) | Ghidra | Native code decompilation |
| **Mach-O** (macOS binaries) | Ghidra | Native code decompilation |
| **Raw Binary** | Ghidra | Custom processor/loader |

### Binary Format Auto-Detection

The server automatically detects binary format and recommends appropriate tools:

```
# For a .NET assembly, you'll see:
⚠️ Compatibility Notice (LIMITED):
Format: .NET Assembly (CLR)
- [WARNING] .NET assemblies have limited native code analysis in Ghidra
  → Use the built-in .NET tools instead: analyze_dotnet(), decompile_dotnet_type()
```

## Configuration Options

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GHIDRA_HOME` | Path to Ghidra installation | Optional (auto-detected) |
| `GHIDRA_PROJECT_DIR` | Custom project directory | Optional (default: `~/.ghidra_projects`) |
| `GHIDRA_TIMEOUT` | Analysis timeout in seconds | Optional (default: 600) |
| `X64DBG_PATH` | Path to x64dbg executable | Optional (dynamic analysis only) |

### Auto-Detection

**Ghidra** is auto-detected from standard paths:
- **Linux**: `/opt/ghidra`, `~/ghidra`, `~/Downloads/ghidra_*`
- **macOS**: `~/Downloads/ghidra_*`, `/Applications/ghidra_*`
- **Windows**: `C:\ghidra`, `C:\Program Files\ghidra`, `%USERPROFILE%\Downloads\ghidra_*`

**ILSpyCmd** is auto-detected from:
- Global dotnet tools: `~/.dotnet/tools/ilspycmd`
- System PATH

## Caching

**Ghidra Cache:**
- Location: `~/.ghidra_mcp_cache/`
- Key: SHA256 hash of binary file
- Benefits: Initial analysis 30-120s, cached queries <1s

**.NET Cache:**
- Location: `~/.dotnet_mcp_cache/`
- Stores: Type listings, decompiled source files
- Benefits: Instant repeated queries

**Clear cache:**
```bash
rm -rf ~/.ghidra_mcp_cache/
rm -rf ~/.dotnet_mcp_cache/
```

## Troubleshooting

### Common Issues

**Ghidra not found:**
```
Error: FileNotFoundError: Ghidra installation not found
```
- Install Ghidra or set `GHIDRA_HOME` environment variable
- Use `diagnose_setup` tool to check detection

**ILSpyCmd not found:**
```
Error: ILSpyCmd not installed
```
- Install .NET SDK: `winget install Microsoft.DotNet.SDK.8`
- Run: `dotnet tool install -g ilspycmd`
- Use `diagnose_dotnet_setup` to verify installation

**ILSpyCmd requires .NET 8 Runtime:**
```
You must install or update .NET to run this application.
Framework: 'Microsoft.NETCore.App', version '8.0.0'
```
- ILSpyCmd is built for .NET 8 - you need the runtime even if you have a newer SDK
- Install .NET 8 Runtime: `winget install Microsoft.DotNet.Runtime.8`
- Multiple .NET runtimes can coexist on your system

**Analysis timeout:**
```
Error: Ghidra analysis timed out
```
- Increase `GHIDRA_TIMEOUT` environment variable
- Try smaller binaries first
- Large/obfuscated binaries may take longer

### Diagnostic Tools

**Check Ghidra setup:**
```
diagnose_setup
```

**Check .NET tools setup:**
```
diagnose_dotnet_setup
```

**Check binary compatibility:**
```
check_binary("/path/to/sample.exe")
```

## Development

### Project Structure

```
binary-mcp/
├── install.ps1                     # Windows interactive installer
├── install.py                      # Linux/macOS interactive installer
├── src/
│   ├── server.py                   # Main MCP server
│   ├── engines/
│   │   ├── static/
│   │   │   ├── ghidra/             # Ghidra integration
│   │   │   │   ├── runner.py       # Process manager
│   │   │   │   ├── project_cache.py # SHA256 caching
│   │   │   │   └── scripts/
│   │   │   │       └── core_analysis.py
│   │   │   └── dotnet/             # .NET integration
│   │   │       └── ilspy_runner.py # ILSpyCmd wrapper
│   │   └── dynamic/x64dbg/         # x64dbg integration
│   │       ├── plugin/             # Plugin DLL
│   │       └── server/             # HTTP server
│   ├── tools/
│   │   ├── dotnet_tools.py         # .NET MCP tools
│   │   └── dynamic_tools.py        # x64dbg MCP tools
│   └── utils/
│       ├── compatibility.py        # Binary format detection
│       ├── patterns.py             # API/crypto patterns
│       └── security.py             # Input validation
├── tests/                          # Test suite
└── pyproject.toml                  # Project config
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src

# Specific test
uv run pytest tests/test_server.py::TestProjectCache
```

## Future Features

Planned enhancements for future releases:

### Linux Dynamic Analysis
- **GDB Integration**: Native Linux debugging with breakpoints, memory inspection, and execution tracing
- **LLDB Support**: macOS/Linux debugging alternative
- **Frida Integration**: Dynamic instrumentation for runtime analysis
- **strace/ltrace**: System call and library call tracing

### Additional Static Analysis
- **Radare2/Rizin**: Alternative disassembly engine
- **Binary Ninja**: Commercial disassembler integration (if licensed)
- **YARA Rules**: Custom pattern matching for malware classification
- **Capa Integration**: Automatic capability detection

### Enhanced .NET Analysis
- **dnSpy Integration**: Advanced .NET debugging (Windows)
- **de4dot**: .NET deobfuscation support
- **Assembly diffing**: Compare .NET assembly versions

Contributions for any of these features are welcome!

## Security Notice

**For defensive security research only.**

- Analyze binaries in isolated environments (VMs, sandboxes)
- Static analysis only - does not execute malware
- No network communication - purely local
- All data cached locally
- Use on samples you have permission to analyze

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Run `pytest` before submitting
5. Submit a pull request

## Resources

- **Ghidra Documentation**: [ghidra-sre.org/CheatSheet.html](https://ghidra-sre.org/CheatSheet.html)
- **ILSpy Project**: [github.com/icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy)
- **MCP Protocol**: [modelcontextprotocol.io](https://modelcontextprotocol.io/)
- **Issues**: [github.com/Sarks0/binary-mcp/issues](https://github.com/Sarks0/binary-mcp/issues)

## License

Apache 2.0 - See LICENSE file for details

## Acknowledgments

- **Ghidra**: NSA's Software Reverse Engineering framework
- **ILSpy/ILSpyCmd**: Open-source .NET decompiler by icsharpcode
- **Anthropic**: Model Context Protocol and Claude
- **FastMCP**: Python MCP framework by @jlowin
