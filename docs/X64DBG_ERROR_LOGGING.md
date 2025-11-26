# X64DBG Error Logging System

**Status:** Implemented
**Date:** 2025-11-26

## Overview

The x64dbg error logging system provides comprehensive error tracking and debugging capabilities for x64dbg operations. Similar to Ghidra's debug logging, all errors are automatically captured, structured, and stored for later analysis.

---

## Features

✅ **Automatic Error Capture** - All HTTP, API, and authentication errors automatically logged
✅ **Structured JSON Storage** - Each error stored as searchable JSON with full context
✅ **Error Statistics** - Track error patterns by operation, type, and HTTP status
✅ **Comprehensive Context** - Captures address, registers, modules, request data
✅ **Performance Tracking** - Records duration in milliseconds for each operation
✅ **Full Stack Traces** - Python tracebacks included for debugging
✅ **Automatic Cleanup** - Keeps most recent 500 errors, removes oldest
✅ **CLI Tools** - View, filter, export, and analyze errors from command line

---

## Architecture

### Storage Location

All errors stored in: `~/.ghidra_mcp_cache/x64dbg_errors/`

### File Structure

```
x64dbg_errors/
├── 20251126_143012_step_into_x64_abc123def456.json    # Individual error
├── 20251126_143015_read_memory_x64_789ghi012jkl.json  # Individual error
├── manifest.json                                       # Error catalog
└── stats.json                                          # Error statistics
```

### Error Record Format

Each error is stored as JSON with the following structure:

```json
{
  "timestamp": 1732604400.123,
  "error_id": "x64_abc123def456",
  "operation": "step_into",
  "error_type": "ConnectionError",
  "error_message": "Failed to connect to x64dbg at 127.0.0.1:8765",
  "http_status": null,
  "api_response": null,
  "endpoint": "/api/step_into",
  "duration_ms": 5123,
  "retry_count": 0,
  "context": {
    "operation": "step_into",
    "address": "0x401000",
    "register": null,
    "module": null,
    "debugger_state": "paused",
    "binary_path": "C:\\malware\\sample.exe",
    "request_data": {
      "address": "0x401000"
    },
    "additional": {
      "url": "http://127.0.0.1:8765/api/step_into",
      "timeout": 30,
      "base_url": "http://127.0.0.1:8765"
    }
  },
  "traceback": "Traceback (most recent call last):\n  File..."
}
```

---

## Error Types Captured

### 1. HTTP Connection Errors
- Plugin not running
- Network timeouts
- Connection refused
- DNS resolution failures

### 2. Authentication Errors
- Token file not found
- Token file empty
- Invalid token
- Expired token (401 responses)

### 3. API Errors
- Plugin returned `success: false`
- Missing required fields
- Invalid address/register formats
- Memory access violations
- Not debugging (no binary loaded)

### 4. Request Errors
- Timeout exceeded
- Malformed JSON responses
- HTTP 4xx/5xx errors
- JSON parsing failures

---

## Usage

### Automatic Logging (Default)

Errors are **automatically logged** whenever x64dbg operations fail. No configuration needed.

```python
from src.engines.dynamic.x64dbg import X64DbgBridge

# Initialize bridge (error logging enabled automatically)
bridge = X64DbgBridge()

# All errors are automatically logged
try:
    bridge.step_into()
except Exception as e:
    # Error already logged with full context to:
    # ~/.ghidra_mcp_cache/x64dbg_errors/
    print(f"Operation failed: {e}")
```

### View Recent Errors

```bash
# Show 20 most recent errors
cd src/engines/dynamic/x64dbg
python view_errors.py

# Show 50 most recent errors
python view_errors.py --count 50
```

**Output:**
```
Showing 20 most recent errors:
Error directory: /Users/user/.ghidra_mcp_cache/x64dbg_errors

ID                   Timestamp            Operation            Error Type
==========================================================================================
x64_abc123def456     2025-11-26 14:30:12  step_into            ConnectionError
x64_789ghi012jkl     2025-11-26 14:28:45  read_memory          RuntimeError
x64_mno345pqr678     2025-11-26 14:25:33  set_breakpoint       RuntimeError

To see details: view_errors.py --error <ERROR_ID>
To see stats:   view_errors.py --stats
```

### View Error Details

```bash
# Show full details for specific error
python view_errors.py --error x64_abc123def456
```

**Output:**
```
================================================================================
ERROR DETAILS: x64_abc123def456
================================================================================

Timestamp:    2025-11-26 14:30:12
Operation:    step_into
Error Type:   ConnectionError
Error Message: Failed to connect to x64dbg: HTTPConnectionPool(host='127.0.0.1', port=8765)
HTTP Status:  None
Endpoint:     /api/step_into
Duration:     5123ms

Context:
{
  "operation": "step_into",
  "address": "0x401000",
  "debugger_state": "paused",
  "binary_path": "C:\\malware\\sample.exe",
  "request_data": {
    "address": "0x401000"
  },
  "additional": {
    "url": "http://127.0.0.1:8765/api/step_into",
    "timeout": 30
  }
}

Traceback:
Traceback (most recent call last):
  File "bridge.py", line 130, in _request
    response = requests.post(url, json=data, headers=headers, timeout=self.timeout)
  ...
```

### View Statistics

```bash
# Show error statistics and patterns
python view_errors.py --stats
```

**Output:**
```
================================================================================
ERROR STATISTICS
================================================================================

Total Errors: 127
Last Error:   2025-11-26 14:30:12

Errors by Operation:
  step_into                    45 ( 35.4%)
  read_memory                  32 ( 25.2%)
  set_breakpoint               18 ( 14.2%)
  get_registers                15 ( 11.8%)
  disassemble                  10 (  7.9%)
  authentication                7 (  5.5%)

Errors by Type:
  ConnectionError              78 ( 61.4%)
  RuntimeError                 35 ( 27.6%)
  TimeoutError                 10 (  7.9%)
  ValueError                    4 (  3.1%)

Errors by HTTP Status:
  401                          12 ( 15.4%)
  500                           8 ( 10.3%)
  503                           5 (  6.4%)
```

### Filter by Operation

```bash
# Show all errors for a specific operation
python view_errors.py --operation step_into
```

**Output:**
```
Found 45 error(s) for operation: step_into

--------------------------------------------------------------------------------
Error ID: x64_abc123def456
Timestamp: 2025-11-26 14:30:12
Message: Failed to connect to x64dbg at 127.0.0.1:8765
Context: {
  "address": "0x401000",
  "debugger_state": "paused"
}
--------------------------------------------------------------------------------
Error ID: x64_def789ghi012
Timestamp: 2025-11-26 14:28:05
Message: API error: Not debugging
Context: {
  "address": "0x402000"
}
```

### Export Errors

```bash
# Export all errors to text file for analysis
python view_errors.py --export x64dbg_errors.txt
```

Creates a comprehensive text log:
```
================================================================================
X64DBG ERROR LOG
Generated: 2025-11-26 14:35:00
Total Errors: 127
================================================================================

Error ID: x64_abc123def456
Timestamp: 2025-11-26 14:30:12
Operation: step_into
Error Type: ConnectionError
Message: Failed to connect to x64dbg at 127.0.0.1:8765
...
```

### Clear Errors

```bash
# Clear all error logs (with confirmation)
python view_errors.py --clear

# Output:
# Are you sure you want to clear all error logs? (yes/no): yes
# Cleared 127 error records
```

---

## CLI Reference

### view_errors.py

**Show recent errors:**
```bash
python view_errors.py [--count N]
```

**Show statistics:**
```bash
python view_errors.py --stats
```

**Show specific error:**
```bash
python view_errors.py --error ERROR_ID
```

**Filter by operation:**
```bash
python view_errors.py --operation OPERATION_NAME
```

**Export to file:**
```bash
python view_errors.py --export OUTPUT_FILE
```

**Clear all errors:**
```bash
python view_errors.py --clear
```

**Custom error directory:**
```bash
python view_errors.py --error-dir /custom/path
```

---

## Programmatic Usage

### Accessing Error Logger

```python
from src.engines.dynamic.x64dbg import X64DbgBridge

bridge = X64DbgBridge()

# Access error logger
error_logger = bridge._error_logger

# Get recent errors
recent = error_logger.get_recent_errors(count=10)

# Get statistics
stats = error_logger.get_stats()

# Get specific error
error = error_logger.get_error("x64_abc123def456")

# Get errors for operation
errors = error_logger.get_errors_by_operation("step_into")
```

### Custom Error Logging

```python
from src.engines.dynamic.x64dbg.error_logger import (
    X64DbgErrorLogger,
    ErrorContext
)

# Initialize logger
logger = X64DbgErrorLogger()

# Log custom error
context = ErrorContext(
    operation="custom_operation",
    address="0x401000",
    additional={"custom_field": "value"}
)

error = RuntimeError("Custom error message")
record = logger.log_error(
    operation="custom_operation",
    error=error,
    context=context
)

print(f"Error logged with ID: {record.error_id}")
```

---

## Configuration

### Error Retention

By default, the system keeps the **500 most recent errors** and automatically removes older ones.

To change:

```python
from src.engines.dynamic.x64dbg.error_logger import X64DbgErrorLogger

# Keep 1000 errors instead
logger = X64DbgErrorLogger(max_errors=1000)
```

### Custom Storage Location

```python
from pathlib import Path

# Custom directory
custom_dir = Path("/custom/error/directory")
logger = X64DbgErrorLogger(error_dir=custom_dir)
```

---

## Error Context Fields

### Standard Fields (Always Present)

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | float | Unix timestamp when error occurred |
| `error_id` | string | Unique error ID (e.g., "x64_abc123") |
| `operation` | string | Operation that failed |
| `error_type` | string | Python exception type |
| `error_message` | string | Error message |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `http_status` | int | HTTP status code if applicable |
| `api_response` | dict | JSON response from API |
| `endpoint` | string | API endpoint that was called |
| `duration_ms` | int | Operation duration in milliseconds |
| `retry_count` | int | Number of retries attempted |
| `traceback` | string | Full Python traceback |

### Context Fields

| Field | Type | Description |
|-------|------|-------------|
| `address` | string | Memory address involved |
| `register` | string | Register name involved |
| `module` | string | Module name involved |
| `debugger_state` | string | Current debugger state |
| `binary_path` | string | Binary being debugged |
| `request_data` | dict | Request parameters sent to API |
| `additional` | dict | Additional context information |

---

## Troubleshooting Common Errors

### Connection Errors

**Symptom:** `ConnectionError: Failed to connect to x64dbg`

**Check:**
1. Is x64dbg running?
2. Is the plugin loaded in x64dbg?
3. Check error log for HTTP status and endpoint
4. Verify port 8765 is accessible

```bash
python view_errors.py --operation authentication
```

### Authentication Errors

**Symptom:** `Authentication failed: Invalid or expired token`

**Solution:**
1. Restart x64dbg to generate new token
2. Check token file exists: `%TEMP%\x64dbg_mcp_token.txt`
3. Review authentication errors:

```bash
python view_errors.py --operation authentication
```

### API Errors

**Symptom:** `RuntimeError: API error: Not debugging`

**Solution:**
1. Load a binary in x64dbg before issuing commands
2. Check current debugger state
3. Review API response in error log:

```bash
python view_errors.py --error <ERROR_ID>
```

### Memory Errors

**Symptom:** `RuntimeError: API error: Failed to read memory`

**Check:**
1. Is address valid?
2. Is memory readable?
3. Check context in error log for address and size:

```bash
python view_errors.py --operation read_memory
```

---

## Comparison with Ghidra Error Logging

| Feature | Ghidra | X64DBG |
|---------|--------|--------|
| **Error Storage** | `ghidra_debug.log` | `~/.ghidra_mcp_cache/x64dbg_errors/` |
| **Format** | Text log | Structured JSON |
| **Error IDs** | None | UUID-based (x64_abc123) |
| **Statistics** | No | Yes (stats.json) |
| **Manifest** | No | Yes (manifest.json) |
| **CLI Tools** | No | Yes (view_errors.py) |
| **Context Capture** | stdout/stderr only | Full request/response/context |
| **Searchability** | grep only | JSON + CLI filtering |
| **Automatic Cleanup** | No | Yes (keeps 500 most recent) |

---

## Performance Impact

**Minimal overhead:**
- Error logging only occurs when errors happen
- JSON writes are async (non-blocking)
- Typical overhead: < 5ms per error
- No impact on successful operations

---

## Best Practices

### 1. Regular Monitoring

```bash
# Check for errors after analysis session
python view_errors.py --count 20
```

### 2. Export for Bug Reports

```bash
# Export errors when reporting issues
python view_errors.py --export bug_report_errors.txt
```

### 3. Pattern Analysis

```bash
# Identify recurring issues
python view_errors.py --stats
```

### 4. Operation-Specific Debugging

```bash
# Focus on specific failing operation
python view_errors.py --operation step_into
```

### 5. Periodic Cleanup

```bash
# Clear old errors periodically (optional)
python view_errors.py --clear
```

---

## Integration with Existing Tools

### MCP Server Integration

Errors are automatically logged when MCP tools call x64dbg operations.

### Session Tracking

Error IDs can be correlated with Ghidra session data using timestamps.

### CI/CD Integration

```bash
# Check for errors in automated tests
python view_errors.py --stats --count 100 | grep "Total Errors: 0" || exit 1
```

---

## Future Enhancements

Potential improvements (not yet implemented):

- [ ] Email/webhook notifications for critical errors
- [ ] Grafana/Prometheus integration for monitoring
- [ ] Error rate alerting
- [ ] Automatic error clustering and classification
- [ ] Integration with GitHub issues
- [ ] Web dashboard for error visualization

---

## Files Reference

| File | Purpose |
|------|---------|
| `src/engines/dynamic/x64dbg/error_logger.py` | Error logging implementation |
| `src/engines/dynamic/x64dbg/bridge.py` | Integration with x64dbg bridge |
| `src/engines/dynamic/x64dbg/view_errors.py` | CLI tool for viewing errors |
| `~/.ghidra_mcp_cache/x64dbg_errors/` | Error storage directory |
| `docs/X64DBG_ERROR_LOGGING.md` | This documentation |

---

## Support

For issues or questions about error logging:

1. Check error logs: `python view_errors.py --stats`
2. Export errors: `python view_errors.py --export errors.txt`
3. Review documentation: `docs/X64DBG_ERROR_LOGGING.md`
4. Report bugs with exported error logs

---

## Changelog

**2025-11-26** - Initial implementation
- Comprehensive error logging system
- JSON-based error storage
- CLI viewing tools
- Statistics tracking
- Automatic cleanup
