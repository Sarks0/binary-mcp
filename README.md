# Binary MCP Server - Static & Dynamic Analysis

[![CI](https://github.com/sarks0/binary-mcp/workflows/CI/badge.svg)](https://github.com/sarks0/binary-mcp/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

A comprehensive Model Context Protocol (MCP) server that provides Claude with advanced binary analysis capabilities through both **static** (Ghidra) and **dynamic** (x64dbg) analysis. Built for defensive security research, malware analysis, and reverse engineering.

## Features

### Static Analysis Tools (13 tools via Ghidra)

**Core Analysis:**
- `analyze_binary` - Run Ghidra headless analysis on a binary
- `get_functions` - List all identified functions with signatures
- `get_imports` - Extract imported functions and libraries
- `get_strings` - Extract strings with cross-references
- `get_xrefs` - Get cross-references for addresses/functions
- `decompile_function` - Decompile to C-like pseudocode

**Enhanced Analysis:**
- `get_call_graph` - Generate function call graphs
- `find_api_calls` - Identify suspicious Windows API calls by category
- `get_memory_map` - Extract memory layout with permissions
- `extract_metadata` - Get binary headers and metadata
- `search_bytes` - Search for byte patterns
- `list_data_types` - List structures and enums
- `detect_crypto` - Identify cryptographic constants
- `generate_iocs` - Extract indicators of compromise
- `diagnose_setup` - Diagnostic checks

### Dynamic Analysis Tools (14 tools via x64dbg) 🆕

**Debugger Control:**
- `x64dbg_connect` - Connect to x64dbg debugger
- `x64dbg_status` - Get current debugger state
- `x64dbg_run` - Start/resume execution
- `x64dbg_pause` - Pause execution
- `x64dbg_step_into` - Step into next instruction
- `x64dbg_step_over` - Step over next instruction

**Breakpoints:**
- `x64dbg_set_breakpoint` - Set breakpoint at address
- `x64dbg_delete_breakpoint` - Delete breakpoint
- `x64dbg_list_breakpoints` - List all breakpoints

**Information:**
- `x64dbg_get_registers` - Get CPU register values
- `x64dbg_read_memory` - Read memory contents
- `x64dbg_disassemble` - Disassemble at address

**Advanced:**
- `x64dbg_trace_execution` - Trace execution for N steps
- `x64dbg_run_to_address` - Run until reaching address

### Key Capabilities

**Static Analysis (Ghidra):**
- **Cross-Platform**: Windows, Linux, macOS support
- **Intelligent Caching**: Fast repeated queries with SHA256-based caching
- **Malware Pattern Detection**: 100+ Windows API patterns categorized by behavior
- **Crypto Detection**: AES, MD5, SHA, RSA, RC4 constants
- **Comprehensive Extraction**: Functions, imports, strings, memory map, control flow
- **IOC Generation**: Automatic extraction of IPs, domains, URLs, file paths, registry keys

**Dynamic Analysis (x64dbg):** 🆕
- **Live Debugging**: Step through code, inspect registers, read memory
- **Breakpoint Management**: Set, delete, and list breakpoints
- **Execution Control**: Run, pause, step into/over, run to address
- **Memory Inspection**: Read memory, disassemble, trace execution
- **HTTP API**: Native C++ plugin with embedded HTTP server
- **Real-time Analysis**: Complement static analysis with dynamic behavior

## Prerequisites

### 1. Ghidra Installation

Download and install Ghidra from: https://ghidra-sre.org/

**Installation Paths** (auto-detected):
- **Linux**: `/opt/ghidra`, `~/ghidra`, `~/Downloads/ghidra_*`
- **macOS**: `~/Downloads/ghidra_*`, `/Applications/ghidra_*`, `/opt/ghidra`
- **Windows**: `C:\ghidra`, `C:\Program Files\ghidra`, `%USERPROFILE%\Downloads\ghidra_*`

Alternatively, set the `GHIDRA_HOME` environment variable:
```bash
export GHIDRA_HOME=/path/to/ghidra_11.2.1_PUBLIC
```

### 2. Java 21+

Ghidra requires Java 21 or later.

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install openjdk-21-jdk
```

**Fedora:**
```bash
sudo dnf install java-21-openjdk
```

**macOS (Homebrew):**
```bash
brew install openjdk@21
```

**Windows:**
Download from: https://adoptium.net/

Verify installation:
```bash
java -version
```

### 3. Python 3.12+

**Ubuntu/Debian:**
```bash
sudo apt install python3.12 python3.12-venv
```

**Fedora:**
```bash
sudo dnf install python3.12
```

**macOS:**
```bash
brew install python@3.12
```

**Windows:**
Download from: https://www.python.org/downloads/

### 4. x64dbg (Optional - for Dynamic Analysis) 🆕

**Windows only** - Download from: https://x64dbg.com/

1. Download the latest release (snapshot recommended)
2. Extract to desired location (e.g., `C:\Program Files\x64dbg`)
3. Run `x64dbg.exe` to verify installation

**Building the MCP Plugin:**
See `src/engines/dynamic/x64dbg/plugin/README.md` for detailed build instructions.

Quick start:
```bash
# Requires Visual Studio 2019+ and CMake
cd src/engines/dynamic/x64dbg/plugin
mkdir build && cd build
cmake .. -DX64DBG_SDK_PATH="path/to/x64dbg_sdk"
cmake --build . --config Release
# Copy x64dbg_mcp.dp64 to x64dbg/x64/plugins/
```

**Note:** Dynamic analysis features are optional. All static analysis features work without x64dbg.

### 5. uv (Python Package Manager)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Or on Windows:
```powershell
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## Installation

1. **Clone or navigate to the repository:**
```bash
# After renaming on GitHub (see GITHUB_RENAME.md)
cd /home/rinzler/Documents/codeProjects/binary-mcp
```

2. **Install dependencies:**
```bash
uv sync
```

3. **Verify installation:**
```bash
uv run python -m src.server
# Should start the MCP server (Ctrl+C to stop)
```

4. **Run diagnostic check:**
```bash
# After configuring Claude, use the diagnose_setup tool
```

## Configuration

### For Claude Desktop

1. **Locate your Claude Desktop config file:**

   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Linux**: `~/.config/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

2. **Add the MCP server configuration:**

```json
{
  "mcpServers": {
    "ghidra-mcp-headless": {
      "command": "uv",
      "args": [
        "--directory",
        "/home/rinzler/Documents/codeProjects/GhidraMCP_headless",
        "run",
        "python",
        "-m",
        "src.server"
      ],
      "env": {
        "GHIDRA_HOME": "/opt/ghidra"
      }
    }
  }
}
```

3. **Adjust paths:**
   - Update `--directory` to your project path
   - Update `GHIDRA_HOME` if Ghidra is in a non-standard location (optional if auto-detection works)

4. **Restart Claude Desktop**

### For Claude Code

1. **Locate your Claude Code config file:**

   - **All platforms**: `~/.config/claude-code/mcp_config.json`

2. **Add the same configuration as above**

3. **Restart Claude Code**

## Usage

### Basic Workflow

1. **Analyze a binary:**
```
Analyze the binary /path/to/malware.exe
```

Claude will call:
```
analyze_binary(binary_path="/path/to/malware.exe")
```

2. **Explore functions:**
```
List all functions in the analyzed binary
```

3. **Decompile suspicious functions:**
```
Decompile the function 'suspicious_function'
```

4. **Find malicious API calls:**
```
Find all suspicious API calls in the binary
```

5. **Generate IOCs:**
```
Extract all indicators of compromise from this malware
```

### Example Analysis Session

**User:** "Analyze /samples/test_malware and identify suspicious behavior"

**Claude:** Uses the following tools:
1. `analyze_binary` - Runs Ghidra analysis
2. `find_api_calls(suspicious_only=True)` - Finds high-risk APIs
3. `generate_iocs` - Extracts network indicators
4. `get_strings(filter_pattern="(http|192\\.)")` - Finds C2 addresses
5. `decompile_function` - Decompiles suspicious functions

**Result:** Comprehensive malware report with:
- Suspicious API usage (process injection, persistence mechanisms)
- Network indicators (C2 servers, exfiltration URLs)
- Behavioral analysis (what the malware does)
- Decompiled code for manual review

### Advanced Usage

**Filter imports by library:**
```
Show me all imports from kernel32.dll
```

**Search for specific patterns:**
```
Search for the byte pattern "4883EC20" in the binary
```

**Analyze call graph:**
```
Show me the call graph for the main function, depth 3
```

**Detect cryptography:**
```
Check if this binary uses any cryptographic algorithms
```

## Tool Reference

### analyze_binary

Analyzes a binary with Ghidra headless mode.

**Parameters:**
- `binary_path` (str, required): Path to binary file
- `force_reanalyze` (bool, optional): Force re-analysis even if cached

**Returns:** Analysis summary with statistics

**Example:**
```
analyze_binary(binary_path="/path/to/malware.exe")
```

### get_functions

Lists all identified functions.

**Parameters:**
- `binary_path` (str, required): Path to analyzed binary
- `filter_name` (str, optional): Filter by name (regex supported)
- `exclude_external` (bool, optional): Exclude external functions (default: True)
- `limit` (int, optional): Max results (default: 100)

**Example:**
```
get_functions(binary_path="/path/to/malware.exe", filter_name="crypto")
```

### find_api_calls

Identifies Windows API calls by category.

**Parameters:**
- `binary_path` (str, required): Path to analyzed binary
- `category` (str, optional): Filter by category (process, memory, file, network, registry, crypto, anti-debug)
- `suspicious_only` (bool, optional): Only return high-risk APIs

**Categories:**
- `process` - Process manipulation (CreateProcess, OpenProcess, TerminateProcess)
- `memory` - Memory operations (VirtualAlloc, WriteProcessMemory)
- `file` - File operations (CreateFile, DeleteFile)
- `network` - Network operations (socket, connect, InternetOpen)
- `registry` - Registry operations (RegCreateKey, RegSetValue)
- `crypto` - Cryptography (CryptEncrypt, CryptDecrypt)
- `anti-debug` - Anti-debugging (IsDebuggerPresent)
- `service` - Service management (CreateService)
- `hooking` - Hooking (SetWindowsHookEx)
- `keylogging` - Keylogging (GetAsyncKeyState)

**Example:**
```
find_api_calls(binary_path="/path/to/malware.exe", category="network", suspicious_only=True)
```

### generate_iocs

Extracts indicators of compromise.

**Extracted IOCs:**
- IP addresses (IPv4)
- Domain names
- URLs (HTTP/HTTPS)
- File paths (Windows/Unix)
- Registry keys
- Email addresses
- Cryptocurrency addresses

**Example:**
```
generate_iocs(binary_path="/path/to/malware.exe")
```

### detect_crypto

Identifies cryptographic algorithms and constants.

**Detects:**
- AES (S-box, round constants)
- MD5 (initialization values)
- SHA-1/SHA-256 (initialization values)
- RSA (common exponents)
- RC4 (S-box initialization)

**Example:**
```
detect_crypto(binary_path="/path/to/malware.exe")
```

## Project Structure

```
GhidraMCP_headless/
├── src/
│   ├── server.py              # Main MCP server with 15+ tools
│   ├── ghidra/
│   │   ├── runner.py          # Ghidra process manager
│   │   ├── project_cache.py   # SHA256-based caching
│   │   └── scripts/
│   │       └── core_analysis.py   # Jython extraction script
│   └── utils/
│       ├── patterns.py        # API/crypto pattern databases
│       └── formatters.py      # Output formatting
├── tests/
│   └── test_server.py         # Pytest test suite
├── config/
│   ├── claude_desktop_config.json
│   └── claude_code_config.json
├── samples/
│   └── test_malware.c         # Sample test binary
├── pyproject.toml             # Project configuration
└── README.md                  # This file
```

## Caching

The server uses SHA256-based caching for fast repeated queries:

- **Cache Location**: `~/.ghidra_mcp_cache/`
- **Cache Key**: SHA256 hash of binary file
- **Cache Contents**: Complete Ghidra analysis results (JSON)
- **Benefits**:
  - Initial analysis: 30-120 seconds (depends on binary size)
  - Cached queries: <1 second
  - Persistent across sessions

**Invalidate cache:**
```bash
rm -rf ~/.ghidra_mcp_cache/
```

## Troubleshooting

### Ghidra Not Found

**Error:** `FileNotFoundError: Ghidra installation not found`

**Solutions:**
1. Install Ghidra from https://ghidra-sre.org/
2. Set `GHIDRA_HOME` environment variable
3. Place Ghidra in a standard location (see Prerequisites)

Use `diagnose_setup` tool to check detection.

### Java Not Found

**Error:** `Java not installed`

**Solution:**
Install Java 21+ (see Prerequisites)

### Analysis Timeout

**Error:** `Ghidra analysis timed out`

**Solutions:**
1. Increase timeout in `runner.py` (default: 600s)
2. Binary may be very large or heavily obfuscated
3. Try on a smaller binary first

### Permission Denied

**Error:** `Permission denied` when analyzing

**Solution:**
Ensure binary has read permissions:
```bash
chmod +r /path/to/binary
```

### Module Import Errors

**Error:** `ModuleNotFoundError: No module named 'mcp'`

**Solution:**
Run with uv:
```bash
uv run python -m src.server
```

## Development

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src

# Run specific test
uv run pytest tests/test_server.py::TestProjectCache
```

### Adding New Tools

1. Add tool function in `src/server.py` with `@app.tool()` decorator
2. Implement analysis logic using cached context
3. Add tests in `tests/test_server.py`
4. Update README with tool documentation

### Extending Pattern Databases

**Add API patterns** in `src/utils/patterns.py`:
```python
"NewAPI": {
    "category": "network",
    "severity": "high",
    "description": "Description of API"
}
```

**Add crypto patterns:**
```python
"algorithm_name": {
    "algorithm": "AES",
    "pattern": "hexpattern",
    "description": "Description"
}
```

## Security Considerations

**This tool is for defensive security research only.**

### Safe Usage

- Analyze binaries in isolated environments (VMs, sandboxes)
- Never run malware directly - only analyze statically
- Use on samples you have permission to analyze
- Follow responsible disclosure for vulnerabilities found

### What This Tool Does

- **Static analysis only** - Reads binary files, does not execute
- **No network communication** - Purely local analysis
- **Caches locally** - All data stays on your machine

### What This Tool Does NOT Do

- Execute malware
- Connect to C2 servers
- Perform dynamic analysis
- Upload binaries anywhere

## License

See LICENSE file for details.

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## Support

- **Issues**: https://github.com/yourusername/ghidra-mcp-headless/issues
- **Discussions**: Use GitHub Discussions for questions
- **Documentation**: See CLAUDE.md for development details

## Acknowledgments

- **Ghidra**: NSA's Software Reverse Engineering (SRE) framework
- **Anthropic**: Model Context Protocol (MCP) and Claude
- **Community**: Malware analysis and reverse engineering community

## Changelog

### v0.1.0 (Initial Release)

- 15+ MCP tools for malware analysis
- Cross-platform Ghidra headless integration
- SHA256-based caching system
- 100+ API pattern database
- Crypto constant detection
- IOC extraction
- Comprehensive test suite
- Claude Desktop and Claude Code support
