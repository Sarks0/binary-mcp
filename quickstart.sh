#!/bin/bash
# Quickstart script for Ghidra MCP Server

set -e

echo "=========================================="
echo "Ghidra MCP Server - Quickstart Setup"
echo "=========================================="
echo ""

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "Error: uv is not installed"
    echo "Install with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Check if Java is installed
if ! command -v java &> /dev/null; then
    echo "Error: Java is not installed"
    echo "Please install Java 21+ and try again"
    exit 1
fi

# Check Java version
java_version=$(java -version 2>&1 | grep -oP 'version "?(1\.)?\K\d+' | head -1)
if [ "$java_version" -lt 21 ]; then
    echo "Warning: Java version $java_version detected. Ghidra requires Java 21+"
fi

# Install dependencies
echo "[1/5] Installing dependencies..."
uv sync --extra dev

# Compile test sample
echo "[2/5] Compiling test malware sample..."
if command -v gcc &> /dev/null; then
    gcc -o samples/test_malware samples/test_malware.c 2>/dev/null || echo "Warning: Sample compilation failed (gcc not found or compilation error)"
else
    echo "Warning: gcc not found, skipping sample compilation"
fi

# Run diagnostics
echo "[3/5] Running diagnostic checks..."
uv run python -c "
from src.ghidra.runner import GhidraRunner
try:
    runner = GhidraRunner()
    diag = runner.diagnose()
    print(f'  Ghidra found: {diag[\"ghidra_path\"]}')
    print(f'  Ghidra version: {diag.get(\"ghidra_version\", \"Unknown\")}')
    print(f'  Java installed: {diag[\"java_installed\"]}')
    if diag['java_version']:
        print(f'  Java version: {diag[\"java_version\"]}')
except Exception as e:
    print(f'  Warning: {e}')
    print('  Please install Ghidra or set GHIDRA_HOME environment variable')
"

# Run tests
echo "[4/5] Running test suite..."
uv run pytest -v --tb=short || echo "Warning: Some tests failed"

# Display next steps
echo ""
echo "[5/5] Setup complete!"
echo ""
echo "=========================================="
echo "Next Steps:"
echo "=========================================="
echo ""
echo "1. Configure Claude Desktop or Claude Code:"
echo "   See config/claude_desktop_config.json"
echo "   See config/claude_code_config.json"
echo ""
echo "2. Update paths in config files:"
echo "   - Update 'directory' to this project path"
echo "   - Update GHIDRA_HOME if needed"
echo ""
echo "3. Copy config to Claude:"
echo "   Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json (macOS)"
echo "                   ~/.config/Claude/claude_desktop_config.json (Linux)"
echo "   Claude Code: ~/.config/claude-code/mcp_config.json"
echo ""
echo "4. Restart Claude Desktop or Claude Code"
echo ""
echo "5. Try it out:"
echo "   'Analyze the binary samples/test_malware'"
echo ""
echo "For more info, see README.md"
echo "=========================================="
