# Claude Code Integration Guide

This guide explains how to use the Binary MCP Server with Claude Code (in addition to Claude Desktop).

## Overview

Claude Code supports MCP servers through configuration files. Once configured, you can use all binary analysis tools directly within your Claude Code sessions.

## Configuration

### Linux/macOS

1. **Locate your Claude Code config directory:**
   ```bash
   # Config is typically at:
   ~/.config/claude-code/
   ```

2. **Create or edit the MCP settings file:**
   ```bash
   # Create the config directory if it doesn't exist
   mkdir -p ~/.config/claude-code

   # Edit the MCP settings
   nano ~/.config/claude-code/mcp_settings.json
   ```

3. **Add the binary-mcp server configuration:**
   ```json
   {
     "mcpServers": {
       "binary-mcp": {
         "command": "uv",
         "args": [
           "--directory",
           "/home/YOUR_USERNAME/Documents/codeProjects/binary-mcp",
           "run",
           "binary-mcp"
         ],
         "env": {
           "GHIDRA_HOME": "/path/to/your/ghidra"
         }
       }
     }
   }
   ```

   **Important:** Replace:
   - `/home/YOUR_USERNAME/Documents/codeProjects/binary-mcp` with your actual binary-mcp installation path
   - `/path/to/your/ghidra` with your actual Ghidra installation path (or remove if Ghidra is already in PATH)

### Windows

1. **Locate your Claude Code config directory:**
   ```powershell
   # Config is typically at:
   %APPDATA%\claude-code\
   ```

2. **Create or edit the MCP settings file:**
   ```powershell
   # Create directory if needed
   New-Item -ItemType Directory -Force -Path "$env:APPDATA\claude-code"

   # Edit the settings
   notepad "$env:APPDATA\claude-code\mcp_settings.json"
   ```

3. **Add the binary-mcp server configuration:**
   ```json
   {
     "mcpServers": {
       "binary-mcp": {
         "command": "uv",
         "args": [
           "--directory",
           "C:\\Users\\YOUR_USERNAME\\Documents\\codeProjects\\binary-mcp",
           "run",
           "binary-mcp"
         ],
         "env": {
           "GHIDRA_HOME": "C:\\ghidra_11.2.1_PUBLIC"
         }
       }
     }
   }
   ```

   **Important:** Replace:
   - `C:\\Users\\YOUR_USERNAME\\Documents\\codeProjects\\binary-mcp` with your actual installation path
   - `C:\\ghidra_11.2.1_PUBLIC` with your Ghidra installation path (or remove if in PATH)

## Alternative Configuration Locations

If the above locations don't work, Claude Code may use:

- **Linux/macOS:**
  - `~/.claude-code/mcp_settings.json`
  - `~/Library/Application Support/ClaudeCode/mcp_settings.json` (macOS)

- **Windows:**
  - `%USERPROFILE%\.claude-code\mcp_settings.json`
  - `%LOCALAPPDATA%\ClaudeCode\mcp_settings.json`

## Verification

1. **Restart Claude Code** after editing the configuration

2. **Test the connection:**
   ```
   In Claude Code, type:
   "diagnose_setup"
   ```

3. **You should see:**
   - Ghidra path detected
   - Java version information
   - Cache and analysis storage statistics

## Available Tools

Once configured, you'll have access to all 20+ analysis tools:

### Core Analysis Tools
- `analyze_binary` - Run Ghidra analysis
- `get_functions` - List functions
- `get_imports` - Extract imports
- `decompile_function` - Decompile to C pseudocode
- `find_api_calls` - Find suspicious APIs
- `generate_iocs` - Extract IOCs

### New: Analysis Storage Tools (Persistent)
- `save_analysis(name, content, binary_path, tags)` - Save analysis for later
- `get_analysis(analysis_id)` - Retrieve saved analysis
- `list_analyses(tag_filter, limit)` - List all saved analyses
- `delete_analysis(analysis_id)` - Delete an analysis
- `append_to_analysis(analysis_id, content)` - Add to existing analysis

### Dynamic Analysis (x64dbg)
- `x64dbg_connect` - Connect to debugger
- `x64dbg_status` - Get debugger state
- `x64dbg_run`, `x64dbg_pause`, `x64dbg_step_into`
- And 11 more debugging tools...

## Usage Examples

### Basic Analysis
```
1. "Analyze the binary at /path/to/sample.exe"
2. "Show me the main function"
3. "Find all suspicious API calls"
4. "Save this analysis as 'Malware Sample XYZ' with tags malware, trojan"
```

### Persistent Analysis Storage
```python
# In one session
save_analysis(
    name="TrojanX Analysis - Initial Findings",
    content="""
    # TrojanX Malware Analysis

    ## Overview
    Detected trojan with network capabilities...

    ## API Calls
    - CreateProcess
    - InternetOpenUrl
    ...
    """,
    binary_path="/samples/trojanx.exe",
    tags=["malware", "trojan", "network"]
)
# Returns: Analysis ID: abc123-def456-...

# Later, in a different session (even if previous crashed)
get_analysis("abc123-def456-...")
# Returns: Full analysis report

# List all saved analyses
list_analyses(tag_filter="malware")
```

## Troubleshooting

### Server Not Detected

1. **Check uv installation:**
   ```bash
   uv --version
   ```

2. **Verify binary-mcp works standalone:**
   ```bash
   cd /path/to/binary-mcp
   uv run binary-mcp
   ```

3. **Check Claude Code logs:**
   - Look for MCP-related errors in Claude Code's debug console
   - Try running Claude Code from terminal to see output

### Ghidra Not Found

1. **Set GHIDRA_HOME explicitly in config:**
   ```json
   "env": {
     "GHIDRA_HOME": "/full/path/to/ghidra"
   }
   ```

2. **Or add Ghidra to PATH before launching Claude Code**

### Permission Errors

On Linux/macOS, ensure the binary-mcp directory is readable:
```bash
chmod -R 755 /path/to/binary-mcp
```

## Benefits of Claude Code Integration

1. **Persistent Storage Survives Crashes:** Analysis reports saved with `save_analysis()` persist across sessions
2. **Code-Aware Analysis:** Combine binary analysis with code understanding
3. **Workflow Integration:** Analyze binaries within your development workflow
4. **Multi-Session Analysis:** Start analysis in Claude Desktop, continue in Claude Code
5. **Search & Retrieve:** Find past analyses by tags or binary name

## Advanced: Multiple Server Instances

You can run the MCP server for both Claude Desktop and Claude Code simultaneously:

**Claude Desktop config** (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "binary-mcp": {
      "command": "uv",
      "args": ["--directory", "/path/to/binary-mcp", "run", "binary-mcp"]
    }
  }
}
```

**Claude Code config** (`~/.config/claude-code/mcp_settings.json`):
```json
{
  "mcpServers": {
    "binary-mcp": {
      "command": "uv",
      "args": ["--directory", "/path/to/binary-mcp", "run", "binary-mcp"]
    }
  }
}
```

Both will share the same cache and analysis storage (`~/.ghidra_mcp_cache/`).

## See Also

- [Installation Guide](INSTALL.md)
- [README](README.md)
- [Contributing](CONTRIBUTING.md)
