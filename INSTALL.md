# Binary MCP Server - Installation Guide

Complete automated installation guide for Windows, Linux, and macOS.

## Quick Start

### Windows (PowerShell)

```powershell
# Run as Administrator
irm https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.ps1 | iex
```

Or download and run locally:

```powershell
# Download
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.ps1" -OutFile "install.ps1"

# Run as Administrator
.\install.ps1
```

### Linux / macOS (Python)

```bash
# One-line install
curl -fsSL https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.py | python3 -

# Or download and run locally
curl -O https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.py
chmod +x install.py
python3 install.py
```

---

## What Gets Installed

### Core Components (All Platforms)
- ✅ **Python 3.12+** (verified, not installed by script)
- ✅ **uv** - Fast Python package manager
- ✅ **Binary MCP Server** - The main server with all dependencies
- ✅ **Claude Desktop Integration** - Automatic MCP configuration

### Platform-Specific Tools

#### Windows
- ✅ **Ghidra** - Static analysis (NSA reverse engineering framework)
- ✅ **x64dbg** - Dynamic analysis (debugger for Windows binaries)
- ✅ **Java 17+** (required for Ghidra, verified only)

#### Linux / macOS
- ✅ **Ghidra** - Static analysis
- ✅ **Java 17+** (required for Ghidra, verified only)

---

## Installation Options

### Windows PowerShell Options

```powershell
# Custom installation directory
.\install.ps1 -InstallDir "C:\Tools\binary-mcp"

# Custom Ghidra location
.\install.ps1 -GhidraDir "C:\Tools\ghidra"

# Skip Ghidra installation
.\install.ps1 -SkipGhidra

# Skip x64dbg installation
.\install.ps1 -SkipX64Dbg

# Don't configure Claude Desktop
.\install.ps1 -NoClaudeConfig

# Combine options
.\install.ps1 -InstallDir "C:\binary-mcp" -SkipX64Dbg
```

### Linux/macOS Python Options

```bash
# Custom installation directory
python3 install.py --install-dir ~/my-binary-mcp

# Skip Ghidra installation
python3 install.py --skip-ghidra

# Don't configure Claude Desktop
python3 install.py --no-claude-config

# Combine options
python3 install.py --install-dir /opt/binary-mcp --skip-ghidra
```

---

## Prerequisites

### All Platforms
- **Python 3.12+** - [Download here](https://www.python.org/downloads/)
- **Internet connection** - For downloading components
- **~2 GB disk space** - For all tools and dependencies

### Windows Specific
- **PowerShell 5.1+** - Built into Windows 10/11
- **Administrator privileges** - For system-wide installation
- **.NET Framework 4.8+** - Usually pre-installed

### Linux/macOS Specific
- **curl** - Usually pre-installed
- **build-essential** (Linux) / **Xcode Command Line Tools** (macOS)

---

## Manual Installation Steps

If you prefer manual installation or the automated scripts fail:

### 1. Install Python 3.12+

**Windows:**
```powershell
winget install Python.Python.3.12
```

**macOS:**
```bash
brew install python@3.12
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install python3.12 python3-pip
```

### 2. Install uv Package Manager

**All Platforms:**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Windows (PowerShell):**
```powershell
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 3. Clone Repository

```bash
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp
```

### 4. Install Dependencies

```bash
uv sync --extra dev
```

### 5. Install Ghidra (Optional)

**Download:** https://github.com/NationalSecurityAgency/ghidra/releases/latest

Extract to your preferred location and set environment variable:

**Windows:**
```powershell
$env:GHIDRA_HOME = "C:\path\to\ghidra"
```

**Linux/macOS:**
```bash
export GHIDRA_HOME=/path/to/ghidra
```

### 6. Install x64dbg (Windows Only, Optional)

**Download:** https://github.com/x64dbg/x64dbg/releases/latest

Extract to your preferred location and set environment variable:

```powershell
$env:X64DBG_HOME = "C:\path\to\x64dbg"
```

### 7. Configure Claude Desktop

**Location:**
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux:** `~/.config/claude/claude_desktop_config.json`

**Configuration:**
```json
{
  "mcpServers": {
    "binary-mcp": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/binary-mcp",
        "run",
        "python",
        "-m",
        "src.server"
      ]
    }
  }
}
```

---

## Verification

After installation, verify everything works:

### 1. Test the Server

```bash
cd ~/binary-mcp
uv run python -m src.server
```

You should see:
```
[INFO] Starting Binary MCP Server...
[INFO] Ghidra detected: /path/to/ghidra
[INFO] Server ready
```

Press `Ctrl+C` to stop.

### 2. Test Ghidra Integration

```bash
cd ~/binary-mcp
uv run python -c "from src.engines.static.ghidra.runner import GhidraRunner; r = GhidraRunner(); print(r.diagnose())"
```

### 3. Test in Claude Desktop

1. **Restart Claude Desktop**
2. Open a new conversation
3. Try: "What binary analysis tools are available?"
4. The server should respond with available tools

---

## Troubleshooting

### Windows Issues

**"Execution policy" error:**
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

**"uv not found" after installation:**
- Restart PowerShell/Terminal
- Or manually add to PATH: `C:\Users\<YourName>\.local\bin`

**x64dbg plugin build fails:**
- Install Visual Studio 2022 with C++ tools
- Or skip dynamic analysis: `.\install.ps1 -SkipX64Dbg`

### Linux/macOS Issues

**"Permission denied" error:**
```bash
chmod +x install.py
```

**Python version too old:**
```bash
# Ubuntu/Debian
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.12

# macOS
brew install python@3.12
```

**Ghidra won't start:**
- Ensure Java 17+ is installed: `java -version`
- Install from: https://adoptium.net/

### Common Issues

**"Claude Desktop config not found":**
- Install Claude Desktop first
- The config file is created on first launch
- Manually create the config file in the correct location

**"Port already in use":**
- Another MCP server might be running
- Change port in the configuration
- Or stop conflicting services

**Git clone fails:**
- The installer will automatically fall back to ZIP download
- Or manually download: https://github.com/Sarks0/binary-mcp/archive/main.zip

---

## Uninstallation

### Windows

```powershell
# Remove installation
Remove-Item -Recurse -Force "$env:USERPROFILE\binary-mcp"
Remove-Item -Recurse -Force "$env:USERPROFILE\ghidra"
Remove-Item -Recurse -Force "$env:USERPROFILE\x64dbg"

# Remove from Claude Desktop config
# Edit: %APPDATA%\Claude\claude_desktop_config.json
# Remove the "binary-mcp" entry from "mcpServers"
```

### Linux/macOS

```bash
# Remove installation
rm -rf ~/binary-mcp
rm -rf ~/ghidra

# Remove from Claude Desktop config
# Edit: ~/.config/claude/claude_desktop_config.json (Linux)
#   or: ~/Library/Application Support/Claude/claude_desktop_config.json (macOS)
# Remove the "binary-mcp" entry from "mcpServers"
```

---

## Upgrading

To update to the latest version:

### Windows
```powershell
cd $env:USERPROFILE\binary-mcp
git pull
uv sync --extra dev
```

### Linux/macOS
```bash
cd ~/binary-mcp
git pull
uv sync --extra dev
```

Or simply re-run the installer - it will update existing installations.

---

## Advanced Configuration

### Custom Environment Variables

**Windows:**
```powershell
# Persistent environment variables
[System.Environment]::SetEnvironmentVariable("GHIDRA_HOME", "C:\custom\ghidra", "User")
[System.Environment]::SetEnvironmentVariable("X64DBG_HOME", "C:\custom\x64dbg", "User")
```

**Linux/macOS:**
```bash
# Add to ~/.bashrc or ~/.zshrc
export GHIDRA_HOME="/custom/path/ghidra"
```

### MCP Server Configuration

The server can be configured via environment variables:

```bash
# Custom cache directory
export GHIDRA_MCP_CACHE="$HOME/custom-cache"

# Enable debug logging
export MCP_LOG_LEVEL="DEBUG"
```

### Running Multiple Instances

You can install multiple copies with different configurations:

```bash
# Production instance
python3 install.py --install-dir ~/binary-mcp-prod

# Development instance with custom Ghidra
python3 install.py --install-dir ~/binary-mcp-dev --ghidra-dir ~/ghidra-dev
```

---

## Getting Help

- **Documentation:** https://github.com/Sarks0/binary-mcp
- **Issues:** https://github.com/Sarks0/binary-mcp/issues
- **Discussions:** https://github.com/Sarks0/binary-mcp/discussions

---

## License

See [LICENSE](LICENSE) file for details.
