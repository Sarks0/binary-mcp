# Binary MCP Server

[![CI](https://github.com/sarks0/binary-mcp/workflows/CI/badge.svg)](https://github.com/sarks0/binary-mcp/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

MCP server providing AI assistants with binary analysis capabilities via Ghidra, ILSpyCmd, and x64dbg. Built for security research and reverse engineering.

## Features

- **Static Analysis**: Native binaries (Ghidra) and .NET assemblies (ILSpyCmd)
- **Dynamic Analysis**: x64dbg debugging with breakpoints and memory inspection
- **Smart Caching**: SHA256-based caching for 30-120x speed improvement
- **Session Management**: Persistent analysis tracking across conversations
- **Pattern Detection**: 100+ Windows API patterns and crypto constants
- **Ghidra 11+/12.x Support**: Automatic PyGhidra integration with backward compatibility

## Quick Start

### Windows

```powershell
# Run interactive installer (as Administrator)
irm https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.ps1 | iex
```

Auto-installs: Python, Java, .NET, Ghidra, x64dbg, and configures Claude.

### Linux / macOS

```bash
# Run interactive installer
curl -sSL https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.py | python3 -
```

Auto-installs prerequisites via package manager (apt/dnf/brew/pacman).

### Manual Installation

```bash
# Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and install
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp
uv sync

# For Ghidra 11+ / 12.x (includes PyGhidra support)
uv sync --extra ghidra11
```

## Configuration

Add to Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

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

Restart Claude after configuration.

## Usage

**Basic Analysis:**
```
Analyze the binary at /path/to/sample.exe
```

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
Find all suspicious Windows API calls
```

**.NET Analysis:**
```
Analyze the .NET assembly at /path/to/app.exe
Decompile the type MyNamespace.MyClass
```

**Dynamic Analysis:**
```
Connect to x64dbg and set a breakpoint at 0x401000
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

### Dynamic Analysis (14 tools)

**x64dbg Integration:**
- `x64dbg_connect`, `x64dbg_status`, `x64dbg_run`, `x64dbg_pause`
- `x64dbg_step_into`, `x64dbg_step_over`
- `x64dbg_set_breakpoint`, `x64dbg_delete_breakpoint`, `x64dbg_list_breakpoints`
- `x64dbg_get_registers`, `x64dbg_read_memory`, `x64dbg_disassemble`
- `x64dbg_trace_execution`, `x64dbg_run_to_address`

### Session Management (7 tools)

- `start_analysis_session` - Begin tracking
- `save_session` - Persist data
- `list_sessions` - List all sessions
- `load_session_section` - Load specific outputs
- `delete_session` - Clean up

## Supported Formats

| Format | Engine | Status |
|--------|--------|--------|
| PE (.exe, .dll, .sys) | Ghidra | ✅ Full |
| .NET Assembly | ILSpyCmd | ✅ Full |
| ELF (Linux) | Ghidra | ✅ Full |
| Mach-O (macOS) | Ghidra | ✅ Full |
| Raw Binary | Ghidra | ⚠️ Limited |

## Ghidra Version Compatibility

Binary MCP automatically detects your Ghidra version and uses the appropriate execution mode:

| Ghidra Version | Execution Mode | Python Runtime | Setup Required |
|----------------|----------------|----------------|----------------|
| 12.x | PyGhidra | Python 3.12+ | `uv sync --extra ghidra11` |
| 11.x | PyGhidra | Python 3.12+ | `uv sync --extra ghidra11` |
| 10.x | analyzeHeadless | Jython 2.7 | None (built-in) |
| 9.x | analyzeHeadless | Jython 2.7 | None (built-in) |

### Ghidra 11+ Setup

Ghidra 11.0+ replaced Jython with PyGhidra (native Python 3). Install the optional dependency:

```bash
# Using pip
pip install pyhidra

# Or install binary-mcp with Ghidra 11+ support
pip install "binary-mcp[ghidra11]"

# Or using uv
uv sync --extra ghidra11
```

The runner automatically detects your Ghidra version. To verify:

```bash
uv run python -c "from src.engines.static.ghidra.runner import GhidraRunner; print(GhidraRunner().diagnose())"
```

To force legacy mode on Ghidra 11+ (not recommended):

```bash
export GHIDRA_USE_LEGACY=1
```

## Troubleshooting

**Ghidra not found:**
```bash
# Set environment variable
export GHIDRA_HOME=/path/to/ghidra

# Or use diagnostic tool
diagnose_setup
```

**"Python is not available" error (Ghidra 11+):**
```bash
# This error occurs when using Ghidra 11+ without PyGhidra
# Install PyGhidra support:
pip install pyhidra

# Verify installation:
uv run python -c "from src.engines.static.ghidra.runner import GhidraRunner; print(GhidraRunner().diagnose())"
```

**ILSpyCmd not found:**
```bash
# Install .NET SDK and ILSpyCmd
dotnet tool install -g ilspycmd

# Verify
diagnose_dotnet_setup
```

**Analysis timeout:**
```bash
# Increase timeout (default: 600s)
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
| `GHIDRA_USE_LEGACY` | Force analyzeHeadless mode on Ghidra 11+ | Not set |
| `GHIDRA_FUNCTION_TIMEOUT` | Per-function decompilation timeout | 30 |
| `GHIDRA_MAX_FUNCTIONS` | Maximum functions to analyze | Unlimited |
| `X64DBG_PATH` | x64dbg executable path | Auto-detected |

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Resources

- **Documentation**: [docs/](docs/)
- **Issues**: [github.com/Sarks0/binary-mcp/issues](https://github.com/Sarks0/binary-mcp/issues)
- **MCP Protocol**: [modelcontextprotocol.io](https://modelcontextprotocol.io/)

## License

Apache 2.0 - See LICENSE file for details.
