# Ghidra MCP Server - Developer Guide

This document provides technical details for developers working on the Ghidra MCP Server project.

## Architecture Overview

### Two-Phase Execution Model

The server uses a two-phase architecture for optimal performance:

#### Phase 1: Analysis (One-time, Slow)
```
Binary File → Ghidra Headless → Jython Script → JSON Export → Cache
```

- **Duration**: 30-120 seconds (depending on binary size)
- **Process**:
  1. User requests analysis via `analyze_binary` tool
  2. Server spawns Ghidra headless process
  3. Ghidra loads binary and runs auto-analysis
  4. Jython script (`core_analysis.py`) extracts comprehensive data
  5. Results saved to JSON file
  6. JSON cached with SHA256 hash of binary as key
  7. Ghidra project optionally kept for incremental queries

#### Phase 2: Querying (Repeated, Fast)
```
Tool Request → Load Cached JSON → Filter/Format → Return Result
```

- **Duration**: <1 second
- **Process**:
  1. User requests specific data (functions, strings, etc.)
  2. Server loads cached JSON (keyed by binary hash)
  3. Filters and formats data according to tool parameters
  4. Returns formatted result to Claude

### Component Architecture

```
┌─────────────────────────────────────────────────┐
│              MCP Server (server.py)              │
│  ┌────────────────────────────────────────────┐ │
│  │         15+ MCP Tool Functions              │ │
│  │  analyze_binary, get_functions, etc.       │ │
│  └────────────────────────────────────────────┘ │
│         ↓                           ↑            │
│  ┌──────────────┐          ┌───────────────┐    │
│  │ GhidraRunner │          │ ProjectCache  │    │
│  │   (runner.py)│          │(project_cache)│    │
│  └──────────────┘          └───────────────┘    │
│         ↓                           ↑            │
│  ┌──────────────────────────────────────────┐   │
│  │    Jython Script (core_analysis.py)      │   │
│  │    Runs inside Ghidra JVM               │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
         ↓                           ↑
   ┌──────────┐              ┌──────────────┐
   │  Ghidra  │              │  JSON Cache  │
   │ Headless │              │ ~/.ghidra_... │
   └──────────┘              └──────────────┘
```

## Core Components

### 1. GhidraRunner (`src/ghidra/runner.py`)

**Responsibilities:**
- Auto-detect Ghidra installation
- Spawn analyzeHeadless processes
- Handle platform-specific differences (Windows .bat vs Unix shell)
- Manage timeouts and error handling

**Key Methods:**

```python
def _detect_ghidra() -> Path:
    """Auto-detect Ghidra across platforms."""
    # Searches standard locations
    # Returns Path to Ghidra installation

def analyze(binary_path, script_path, output_path, ...) -> dict:
    """Run Ghidra headless analysis."""
    # Builds command line
    # Spawns subprocess with timeout
    # Returns analysis metadata
```

**Platform Detection:**
- macOS: `~/Downloads/ghidra_*`, `~/ghidra`, `/Applications/ghidra_*`
- Linux: `/opt/ghidra`, `~/ghidra`, `~/Downloads/ghidra_*`
- Windows: `C:\ghidra`, `%USERPROFILE%\Downloads\ghidra_*`, Program Files

### 2. ProjectCache (`src/ghidra/project_cache.py`)

**Responsibilities:**
- SHA256-based caching of analysis results
- Metadata tracking (binary path, hash, timestamp)
- Cache management (list, invalidate, clear)

**Key Methods:**

```python
def get_cached(binary_path: str) -> Optional[dict]:
    """Retrieve cached analysis if exists."""
    # Calculate SHA256 of binary
    # Check if cache file exists
    # Load and return JSON

def save_cached(binary_path: str, data: dict) -> bool:
    """Save analysis to cache."""
    # Calculate SHA256
    # Write JSON to cache dir
    # Write metadata file
```

**Cache Structure:**
```
~/.ghidra_mcp_cache/
├── <sha256_hash>.json       # Analysis data
├── <sha256_hash>.meta.json  # Metadata
└── ...
```

### 3. Jython Script (`src/ghidra/scripts/core_analysis.py`)

**Runs inside Ghidra's JVM** - uses Ghidra's Python 2 interpreter with Java interop.

**Responsibilities:**
- Extract comprehensive analysis data
- Access Ghidra's program database APIs
- Decompile functions
- Export to JSON

**Key Ghidra APIs Used:**

```python
# Program access
currentProgram           # The loaded binary
listing                  # Code units, instructions
function_manager         # All functions
symbol_table            # Symbols, labels
memory                  # Memory blocks
reference_manager       # Cross-references
data_type_manager       # Structures, enums

# Decompilation
DecompInterface         # Decompiler
DecompileOptions        # Decompiler settings
```

**Extracted Data:**

```json
{
  "metadata": {
    "name": "binary.exe",
    "executable_format": "PE",
    "language": "x86:LE:64:default",
    "image_base": "0x400000",
    ...
  },
  "functions": [
    {
      "name": "main",
      "address": "0x401000",
      "signature": "int main(int argc, char **argv)",
      "parameters": [...],
      "local_variables": [...],
      "called_functions": [...],
      "pseudocode": "int main(void) { ... }",
      "basic_blocks": [...]
    }
  ],
  "imports": [...],
  "exports": [...],
  "strings": [...],
  "memory_map": [...],
  "data_types": {
    "structures": [...],
    "enums": [...]
  }
}
```

### 4. Pattern Databases (`src/utils/patterns.py`)

**APIPatterns Class:**
- Database of 100+ Windows API functions
- Categorized by behavior (process, memory, file, network, etc.)
- Severity ratings (critical, high, medium, low)
- Used by `find_api_calls` tool

**Categories:**
- `process` - Process manipulation
- `memory` - Memory operations
- `file` - File I/O
- `network` - Network communication
- `registry` - Registry operations
- `crypto` - Cryptography
- `anti-debug` - Anti-debugging
- `service` - Service management
- `hooking` - Hooking mechanisms
- `keylogging` - Keyboard logging

**CryptoPatterns Class:**
- Database of cryptographic constants
- Detects AES, MD5, SHA-1/256, RSA, RC4
- Searches in strings and function names

### 5. MCP Server (`src/server.py`)

**Responsibilities:**
- Implement MCP protocol
- Expose tools to Claude
- Coordinate between components
- Format results for display

**Tool Implementation Pattern:**

```python
@app.tool()
def tool_name(
    binary_path: str,
    param1: Optional[str] = None,
    param2: int = 100
) -> str:
    """
    Tool description for Claude.

    Args:
        binary_path: Description
        param1: Description
        param2: Description

    Returns:
        Description of return value
    """
    try:
        # Get cached analysis context
        context = get_analysis_context(binary_path)

        # Extract relevant data
        data = context.get("key", [])

        # Apply filters
        if param1:
            data = [item for item in data if matches(item, param1)]

        # Limit results
        data = data[:param2]

        # Format output
        result = format_output(data)

        return result

    except Exception as e:
        logger.error(f"tool_name failed: {e}")
        return f"Error: {e}"
```

## Development Workflow

### Setting Up Development Environment

```bash
# Clone repository
cd /home/rinzler/Documents/codeProjects/GhidraMCP_headless

# Install dependencies
uv sync

# Install dev dependencies
uv sync --extra dev

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=src --cov-report=html
```

### Running the Server Locally

```bash
# Run MCP server (stdio mode)
uv run python -m src.server

# The server will:
# - Initialize GhidraRunner
# - Initialize ProjectCache
# - Load pattern databases
# - Listen for MCP requests on stdin/stdout
```

### Testing Individual Components

```bash
# Test Ghidra runner
uv run python -c "from src.ghidra.runner import GhidraRunner; r = GhidraRunner(); print(r.diagnose())"

# Test project cache
uv run python -c "from src.ghidra.project_cache import ProjectCache; c = ProjectCache(); print(c.cache_dir)"

# Test pattern databases
uv run python -c "from src.utils.patterns import APIPatterns; p = APIPatterns(); print(p.get_api_info('CreateRemoteThread'))"
```

### Adding a New Tool

1. **Define the tool function** in `src/server.py`:

```python
@app.tool()
def my_new_tool(
    binary_path: str,
    my_param: str = "default"
) -> str:
    """
    Description of what this tool does.

    Args:
        binary_path: Path to analyzed binary
        my_param: Description of parameter

    Returns:
        Description of output
    """
    try:
        context = get_analysis_context(binary_path)

        # Your analysis logic here
        result = analyze_something(context, my_param)

        # Format and return
        return format_result(result)

    except Exception as e:
        logger.error(f"my_new_tool failed: {e}")
        return f"Error: {e}"
```

2. **Add tests** in `tests/test_server.py`:

```python
def test_my_new_tool(mock_context):
    """Test my new tool."""
    # Mock get_analysis_context to return mock_context
    # Call tool function
    # Assert expected output
    pass
```

3. **Update README.md** with tool documentation

4. **Update config files** if needed

### Extending the Jython Script

To extract additional data from Ghidra:

1. **Edit** `src/ghidra/scripts/core_analysis.py`
2. **Access Ghidra APIs** to extract new data
3. **Add to context dict** for JSON export
4. **Test** with a sample binary

Example - Adding exception handlers:

```python
# In extract_comprehensive_analysis()
context["exception_handlers"] = []

for func in function_iterator:
    try:
        # Get exception handlers for function
        handlers = func.getExceptionHandlers()
        for handler in handlers:
            context["exception_handlers"].append({
                "function": func.getName(),
                "address": str(handler.getAddress()),
                "type": str(handler.getType())
            })
    except Exception as e:
        logger.warning(f"Error extracting handlers: {e}")
```

### Performance Optimization

**Current Bottlenecks:**
1. Initial Ghidra analysis (30-120s) - unavoidable
2. Decompilation (5-10s per function) - can be optimized
3. Large JSON files (>100MB for big binaries) - can use streaming

**Optimization Strategies:**

1. **Selective Decompilation:**
```python
# Don't decompile all functions upfront
# Decompile on-demand when requested
if tool == "decompile_function":
    # Decompile only this function
    pass
```

2. **Incremental Analysis:**
```python
# Keep Ghidra project persistent
# Re-use analysis for subsequent runs
keep_project=True
```

3. **Pagination:**
```python
# For large datasets, implement pagination
def get_functions(binary_path, offset=0, limit=100):
    functions = context["functions"][offset:offset+limit]
    return functions
```

4. **Background Processing:**
```python
# Queue analysis jobs
# Process in background
# Poll for completion
```

## Testing Strategy

### Unit Tests

Test individual components in isolation:

```python
# Test cache operations
def test_cache_save_and_load():
    cache = ProjectCache()
    cache.save_cached(binary_path, data)
    cached = cache.get_cached(binary_path)
    assert cached == data
```

### Integration Tests

Test components working together:

```python
# Test full analysis workflow
def test_analyze_binary_end_to_end():
    runner = GhidraRunner()
    cache = ProjectCache()

    # Run analysis
    result = runner.analyze(binary, script, output)

    # Check cache
    assert cache.has_cached(binary)
```

### Mock Testing

Mock Ghidra for faster tests:

```python
@patch('src.server.get_analysis_context')
def test_tool_with_mock(mock_get_context):
    mock_get_context.return_value = mock_context
    result = tool_function(binary_path)
    assert "expected" in result
```

## Debugging

### Enable Debug Logging

```python
# In src/server.py
logging.basicConfig(level=logging.DEBUG)
```

### Inspect Cached Data

```bash
# View cached JSON
cat ~/.ghidra_mcp_cache/<hash>.json | jq .

# View metadata
cat ~/.ghidra_mcp_cache/<hash>.meta.json | jq .
```

### Test Ghidra Script Independently

```bash
# Run Ghidra headless with script
$GHIDRA_HOME/support/analyzeHeadless \
  /tmp/test_project TestProject \
  -import /path/to/binary \
  -scriptPath ./src/ghidra/scripts \
  -postScript core_analysis.py \
  -deleteProject

# Check output
cat /tmp/ghidra_context.json | jq .
```

### Common Issues

**Issue:** "Module 'mcp' not found"
**Solution:** Run with `uv run python -m src.server`

**Issue:** "Ghidra not found"
**Solution:** Set `GHIDRA_HOME` or install in standard location

**Issue:** "Analysis timeout"
**Solution:** Increase timeout in `runner.analyze(timeout=1200)`

**Issue:** "Decompilation failed"
**Solution:** Some functions can't be decompiled (external, thunks, obfuscated)

## Security Considerations

### Input Validation

```python
# Validate binary path
if not Path(binary_path).exists():
    raise FileNotFoundError(f"Binary not found: {binary_path}")

# Validate binary size
max_size = 100 * 1024 * 1024  # 100MB
if Path(binary_path).stat().st_size > max_size:
    raise ValueError("Binary too large")
```

### Sandboxing

- Ghidra runs in separate JVM process
- No code execution - static analysis only
- Consider running in Docker/VM for extra isolation

### Resource Limits

```python
# Timeout protection
runner.analyze(binary, timeout=600)

# Memory limits (via Ghidra JVM args)
-Xmx4G  # Max 4GB heap
```

## Future Enhancements

### Planned Features

1. **YARA Integration:**
```python
def apply_yara_rules(binary_path: str, rules_path: str):
    """Scan binary with YARA rules."""
    import yara
    rules = yara.compile(filepath=rules_path)
    matches = rules.match(binary_path)
    return format_yara_results(matches)
```

2. **Binary Diffing:**
```python
def diff_binaries(binary1: str, binary2: str):
    """Compare two binaries."""
    context1 = get_analysis_context(binary1)
    context2 = get_analysis_context(binary2)
    return compute_diff(context1, context2)
```

3. **Advanced Call Graph:**
```python
def get_advanced_call_graph(binary_path: str, format: str = "dot"):
    """Export call graph in various formats."""
    # Generate DOT/GraphML/etc.
    pass
```

4. **Taint Analysis:**
```python
def trace_data_flow(binary_path: str, source_func: str, sink_func: str):
    """Track data flow from source to sink."""
    # Use Ghidra's P-code for dataflow analysis
    pass
```

## Contributing Guidelines

1. **Code Style**: Follow PEP 8, use type hints
2. **Testing**: Add tests for new features (target: >80% coverage)
3. **Documentation**: Update README.md and CLAUDE.md
4. **Commits**: Use conventional commits (feat:, fix:, docs:, etc.)
5. **Pull Requests**: Include description, tests, documentation

## Resources

- **Ghidra Documentation**: https://ghidra.re/
- **Ghidra API**: https://ghidra.re/ghidra_docs/api/
- **MCP Protocol**: https://modelcontextprotocol.io/
- **FastMCP**: https://github.com/jlowin/fastmcp
- **uv**: https://docs.astral.sh/uv/

## Maintainers

- Primary: Rinzler

## License

See LICENSE file for details.
