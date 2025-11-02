# Binary MCP Server

[![CI](https://github.com/sarks0/binary-mcp/workflows/CI/badge.svg)](https://github.com/sarks0/binary-mcp/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Model Context Protocol (MCP) server that provides AI assistants with binary analysis capabilities using Ghidra (static) and x64dbg (dynamic). Built for security research, malware analysis, and reverse engineering.

## Features

- **Static Analysis**: Ghidra integration with decompilation, function extraction, and pattern detection
- **Dynamic Analysis**: x64dbg debugging with breakpoints, memory inspection, and execution tracing
- **Intelligent Caching**: SHA256-based caching for fast repeated queries
- **Session System**: Incremental analysis storage with compression for large binaries
- **Malware Detection**: 100+ Windows API patterns and cryptographic constant detection

## Quick Start

### Prerequisites

1. **Ghidra** - Download from [ghidra-sre.org](https://ghidra-sre.org/)
2. **Java 21+** - Required by Ghidra
3. **Python 3.12+**
4. **x64dbg** (optional) - For dynamic analysis on Windows
   - Requires x64dbg plugin (see [x64dbg plugin README](src/engines/dynamic/x64dbg/plugin/README.md))
   - Uses external process architecture for stability

### Installation

```bash
# Clone repository
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp

# Install dependencies
uv sync

# Verify installation
uv run python -m src.server
```

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
- Run Ghidra analysis
- Extract functions, imports, exports, and strings
- Identify suspicious API calls
- Decompile key functions

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

### Analysis Sessions

For large binaries or multi-step analysis:

```
Start an analysis session for /path/to/malware.exe with tags: ransomware, apt28
```

Sessions save all tool outputs incrementally, allowing you to:
- Continue analysis across conversations
- Load specific sections to avoid context overflow
- Recover from crashes or token limits

**Session Management:**
```
# List all sessions
list_sessions()

# Get session summary
get_session_summary("session-id")

# Load specific tool outputs
load_session_section("session-id", "tools", "find_api_calls")

# Delete when done
delete_session("session-id")
```

## Available Tools

### Static Analysis (22 tools)

**Core Analysis:**
- `analyze_binary` - Run Ghidra headless analysis
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

**Session System:**
- `start_analysis_session` - Begin tracking analysis outputs
- `save_session` - Persist session data (compressed)
- `list_sessions` - List all sessions with filters
- `get_session_summary` - Get session metadata
- `load_session_section` - Load specific tool outputs
- `load_full_session` - Load complete session
- `delete_session` - Clean up sessions

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

## Configuration Options

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GHIDRA_HOME` | Path to Ghidra installation | Optional (auto-detected) |
| `GHIDRA_PROJECT_DIR` | Custom project directory | Optional (default: `~/.ghidra_projects`) |
| `GHIDRA_TIMEOUT` | Analysis timeout in seconds | Optional (default: 600) |
| `X64DBG_PATH` | Path to x64dbg executable | Optional (dynamic analysis only) |

### Auto-Detection

Ghidra is auto-detected from standard paths:
- **Linux**: `/opt/ghidra`, `~/ghidra`, `~/Downloads/ghidra_*`
- **macOS**: `~/Downloads/ghidra_*`, `/Applications/ghidra_*`
- **Windows**: `C:\ghidra`, `C:\Program Files\ghidra`, `%USERPROFILE%\Downloads\ghidra_*`

## Supported Formats

- **PE**: Windows executables (`.exe`, `.dll`, `.sys`)
- **ELF**: Linux binaries
- **Mach-O**: macOS binaries
- **Raw Binary**: Custom processor/loader specification

## Caching

- **Location**: `~/.ghidra_mcp_cache/`
- **Key**: SHA256 hash of binary file
- **Benefits**: Initial analysis 30-120s, cached queries <1s

**Clear cache:**
```bash
rm -rf ~/.ghidra_mcp_cache/
```

## Troubleshooting

### Common Issues

**Ghidra not found:**
```
Error: FileNotFoundError: Ghidra installation not found
```
- Install Ghidra or set `GHIDRA_HOME` environment variable
- Use `diagnose_setup` tool to check detection

**Analysis timeout:**
```
Error: Ghidra analysis timed out
```
- Increase `GHIDRA_TIMEOUT` environment variable
- Try smaller binaries first
- Large/obfuscated binaries may take longer

**Permission denied:**
```
Error: Permission denied
```
- Ensure binary has read permissions: `chmod +r /path/to/binary`

**Invalid loader name:**
```
Error: Invalid loader name specified
```
- Server auto-detects loaders (PeLoader, ElfLoader, etc.)
- Update to latest version if using old config

### Diagnostic Tool

After configuration, use the diagnostic tool:
```
diagnose_setup
```

This checks:
- Ghidra installation and path
- Java version
- Python dependencies
- Cache directory permissions

## Development

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src

# Specific test
uv run pytest tests/test_server.py::TestProjectCache
```

### Project Structure

```
binary-mcp/
├── src/
│   ├── server.py                   # Main MCP server
│   ├── engines/
│   │   ├── static/ghidra/          # Ghidra integration
│   │   │   ├── runner.py           # Process manager
│   │   │   ├── project_cache.py    # SHA256 caching
│   │   │   └── scripts/
│   │   │       └── core_analysis.py # Jython extraction
│   │   └── dynamic/x64dbg/         # x64dbg integration (external process)
│   │       ├── ARCHITECTURE.md     # Architecture documentation
│   │       ├── pipe_protocol.h     # IPC protocol definitions
│   │       ├── plugin/             # Plugin DLL (minimal stub)
│   │       └── server/             # HTTP server (separate process)
│   └── utils/
│       ├── patterns.py             # API/crypto patterns
│       └── session_manager.py      # Session storage
├── tests/                          # Test suite
└── pyproject.toml                  # Project config
```

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
- **MCP Protocol**: [modelcontextprotocol.io](https://modelcontextprotocol.io/)
- **Issues**: [github.com/Sarks0/binary-mcp/issues](https://github.com/Sarks0/binary-mcp/issues)

## License

Apache 2.0 - See LICENSE file for details

## Acknowledgments

- **Ghidra**: NSA's Software Reverse Engineering framework
- **Anthropic**: Model Context Protocol and Claude
- **FastMCP**: Python MCP framework by @jlowin
