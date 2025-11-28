# x64dbg MCP Bridge Plugin

Native x64dbg plugin that exposes debugger functionality via HTTP API for integration with the binary-mcp server.

## Architecture

**External Process Design** - The plugin uses a two-process architecture for stability:

```
┌──────────────────────────────────────────────────────────┐
│ x64dbg.exe Process                                       │
│                                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │ x64dbg_mcp.dp64 (Plugin DLL - Minimal Stub)    │   │
│  │                                                  │   │
│  │  • Spawns HTTP server process                  │   │
│  │  • Creates Named Pipe server                   │   │
│  │  • Handles x64dbg API calls                    │   │
│  │  • Named Pipe: \\.pipe\x64dbg_mcp              │   │
│  │                                                  │   │
│  │              ↕ Named Pipe IPC                   │   │
│  └──────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
                          ↕
┌──────────────────────────────────────────────────────────┐
│ x64dbg_mcp_server.exe (Separate Process)                │
│                                                           │
│  • HTTP Server on port 8765                             │
│  • Isolated from x64dbg crashes                         │
│  • Communicates via Named Pipe                          │
│  • Can restart without restarting x64dbg               │
│                                                           │
│              ↕ HTTP                                      │
└──────────────────────────────────────────────────────────┘
                          ↕
         MCP Server (Python) via bridge.py
```

**Why External Process?**
- Prevents x64dbg crashes from HTTP server issues
- Avoids Windows loader lock restrictions
- No DEP/BEX64 violations
- Easy to debug independently
- Industry-standard plugin pattern

See [ARCHITECTURE.md](../ARCHITECTURE.md) for detailed technical documentation.

## Building

### Prerequisites

1. **Visual Studio 2019+** (with C++ workload)
2. **CMake 3.20+**
3. **x64dbg Plugin SDK**

### Download x64dbg SDK

```bash
# Clone x64dbg repository
git clone https://github.com/x64dbg/x64dbg.git

# Copy SDK to project
mkdir -p extern/x64dbg_sdk
cp -r x64dbg/src/sdk/* extern/x64dbg_sdk/
```

### Build Plugin

The build system creates **two files**:
1. **x64dbg_mcp.dp64** (or .dp32) - Plugin DLL
2. **x64dbg_mcp_server.exe** - HTTP server executable

```bash
# Navigate to plugin directory
cd src/engines/dynamic/x64dbg/plugin

# Create build directory
mkdir build && cd build

# Configure CMake
cmake .. -DX64DBG_SDK_PATH="../../../../../../extern/x64dbg_sdk"

# Build (creates BOTH plugin and server)
cmake --build . --config Release

# Output files:
#   - x64dbg_mcp.dp64 (plugin DLL)
#   - x64dbg_mcp_server.exe (HTTP server)
```

### Install Plugin

**IMPORTANT**: Both files must be deployed together in the same directory!

```bash
# Option 1: Manual install (copy BOTH files)
cp build/Release/x64dbg_mcp.dp64 "C:/Program Files/x64dbg/x64/plugins/"
cp build/Release/x64dbg_mcp_server.exe "C:/Program Files/x64dbg/x64/plugins/"

# Option 2: Auto-install (set environment variable)
set X64DBG_DIR=C:/Program Files/x64dbg/x64
cmake --build . --config Release
# Both files are automatically copied to %X64DBG_DIR%/plugins/
```

**Deployment Structure:**
```
C:\Program Files\x64dbg\x64\plugins\
├── x64dbg_mcp.dp64           # Plugin (loaded by x64dbg)
└── x64dbg_mcp_server.exe     # Server (spawned by plugin)
```

## API Endpoints

Base URL: `http://localhost:8765`

**Note**: The HTTP server runs as a separate process (`x64dbg_mcp_server.exe`) spawned automatically by the plugin. Requests are forwarded to the plugin via Named Pipe IPC.

### Debugger Control

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET/POST | Get debugger status |
| `/api/load` | POST | Load binary into debugger |
| `/api/run` | POST | Start/resume execution |
| `/api/pause` | POST | Pause execution |
| `/api/step_into` | POST | Step into next instruction |
| `/api/step_over` | POST | Step over next instruction |
| `/api/step_out` | POST | Step out of current function |

### Wait/Synchronization (NEW)

Essential for automation scripts - block until debugger reaches desired state.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/wait/paused` | POST | Wait until debugger pauses (breakpoint, exception) |
| `/api/wait/running` | POST | Wait until debugger is running |
| `/api/wait/debugging` | POST | Wait until binary is loaded |

**Parameters** (JSON body):
- `timeout`: Maximum wait time in milliseconds (default: 30000, max: 300000)

### Breakpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/breakpoint/set` | POST | Set breakpoint at address |
| `/api/breakpoint/delete` | POST | Delete breakpoint |
| `/api/breakpoint/list` | GET | List all breakpoints |

### Information

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/registers` | GET | Get all register values |
| `/api/stack` | GET | Get stack trace |
| `/api/modules` | GET | List loaded modules |
| `/api/threads` | GET | List threads |

### Memory

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/memory/read` | POST | Read memory |
| `/api/memory/write` | POST | Write memory |
| `/api/disassemble` | POST | Disassemble at address |

### Memory Allocation (NEW - Phase 3)

Memory management functions for advanced debugging and analysis.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/memory/alloc` | POST | Allocate memory in debugee's address space |
| `/api/memory/free` | POST | Free previously allocated memory |
| `/api/memory/protect` | POST | Change memory protection (rwx, rx, rw, etc.) |
| `/api/memory/set` | POST | Fill memory with a byte value (memset) |
| `/api/memory/check` | POST | Check if address is readable |

**Parameters:**

`/api/memory/alloc`:
- `size`: Number of bytes to allocate (default: 4096, max: 16MB)
- `address`: Optional preferred address

`/api/memory/protect`:
- `address`: Memory address
- `protection`: "rwx", "rx", "rw", "r", "x", or "n" (none)
- `size`: Size in bytes (default: 4096)

`/api/memory/set`:
- `address`: Start address
- `value`: Byte value (0-255)
- `size`: Number of bytes to fill

### Enhanced Breakpoints (NEW - Phase 3)

Extended breakpoint functionality for all breakpoint types.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/breakpoint/toggle` | POST | Enable/disable software breakpoint |
| `/api/breakpoint/hardware/delete` | POST | Delete hardware breakpoint |
| `/api/breakpoint/hardware/toggle` | POST | Enable/disable hardware breakpoint |
| `/api/breakpoint/memory/toggle` | POST | Enable/disable memory breakpoint |
| `/api/breakpoint/list/all` | GET/POST | List all breakpoints (software, hardware, memory) |

**Parameters:**
- `address`: Breakpoint address
- `enable`: 1 to enable, 0 to disable (for toggle endpoints)

### Events (NEW - Phase 2)

Debug event system for capturing breakpoints, exceptions, and other debug events.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/events` | POST | Get pending events from queue |
| `/api/events/clear` | POST | Clear event queue |
| `/api/events/status` | GET/POST | Get event system status |

**Event Types:**
- `breakpoint_hit` - Breakpoint triggered
- `exception` - Exception occurred
- `paused` - Debugger paused
- `running` - Debugger resumed
- `stepped` - Single step completed
- `process_started` - Process created
- `process_exited` - Process terminated
- `thread_created` - New thread created
- `thread_exited` - Thread terminated
- `module_loaded` - DLL/module loaded
- `module_unloaded` - DLL/module unloaded
- `system_breakpoint` - Initial system breakpoint

## API Examples

### Get Status
```bash
curl http://localhost:8765/api/status
```

Response:
```json
{
  "success": true,
  "state": "paused",
  "binary_loaded": true,
  "binary_path": "C:\\malware.exe",
  "is_running": false,
  "current_address": "00401234"
}
```

### Step Into
```bash
curl -X POST http://localhost:8765/api/step_into
```

Response:
```json
{
  "success": true,
  "address": "00401235"
}
```

### Get Registers
```bash
curl http://localhost:8765/api/registers
```

Response:
```json
{
  "success": true,
  "rax": "0000000000000000",
  "rbx": "0000000000000001",
  "rcx": "00007FF7ABCD1234",
  ...
}
```

### Wait for Breakpoint (NEW)
```bash
# Start execution
curl -X POST http://localhost:8765/api/run

# Wait up to 60 seconds for breakpoint/exception
curl -X POST http://localhost:8765/api/wait/paused \
  -H "Content-Type: application/json" \
  -d '{"timeout": 60000}'
```

Response (success):
```json
{
  "success": true,
  "state": "paused",
  "elapsed_ms": "1234",
  "current_address": "0x00401234"
}
```

Response (timeout):
```json
{
  "success": false,
  "error": "Timeout waiting for debugger to pause",
  "timeout_ms": "60000",
  "elapsed_ms": "60000",
  "current_state": "running"
}
```

### Get Debug Events (NEW)
```bash
# Get up to 50 events from queue
curl -X POST http://localhost:8765/api/events \
  -H "Content-Type: application/json" \
  -d '{"max_events": 50}'
```

Response:
```json
{
  "success": true,
  "events": [
    {
      "id": 1,
      "type": "process_started",
      "timestamp": 0,
      "address": "0x00400000",
      "thread_id": 1234,
      "module": "C:\\malware.exe",
      "details": "base=0x400000"
    },
    {
      "id": 2,
      "type": "module_loaded",
      "timestamp": 15,
      "address": "0x76D00000",
      "thread_id": 0,
      "module": "C:\\Windows\\System32\\kernel32.dll"
    },
    {
      "id": 3,
      "type": "breakpoint_hit",
      "timestamp": 1234,
      "address": "0x00401000",
      "thread_id": 1234,
      "details": "name=;type=0;enabled=1"
    }
  ],
  "queue_size": 0,
  "next_event_id": 4
}
```

### Allocate Memory (NEW - Phase 3)
```bash
# Allocate 4KB of memory
curl -X POST http://localhost:8765/api/memory/alloc \
  -H "Content-Type: application/json" \
  -d '{"size": 4096}'
```

Response:
```json
{
  "success": true,
  "address": "12340000",
  "size": 4096
}
```

### Change Memory Protection (NEW - Phase 3)
```bash
# Make code region writable for patching
curl -X POST http://localhost:8765/api/memory/protect \
  -H "Content-Type: application/json" \
  -d '{"address": "401000", "protection": "rwx", "size": 4096}'
```

Response:
```json
{
  "success": true,
  "address": "401000",
  "protection": 64
}
```

### Fill Memory (NEW - Phase 3)
```bash
# Fill memory with NOPs (0x90)
curl -X POST http://localhost:8765/api/memory/set \
  -H "Content-Type: application/json" \
  -d '{"address": "401000", "value": 144, "size": 10}'
```

Response:
```json
{
  "success": true,
  "address": "401000",
  "size": 10,
  "value": 144
}
```

### List All Breakpoints (NEW - Phase 3)
```bash
curl http://localhost:8765/api/breakpoint/list/all
```

Response:
```json
{
  "success": true,
  "breakpoints": {
    "software": [
      {"address": "401000", "enabled": true, "singleshoot": false}
    ],
    "hardware": [
      {"address": "500000", "enabled": true, "type": "write", "size": 4}
    ],
    "memory": []
  }
}
```

## Development

### Project Structure

```
src/engines/dynamic/x64dbg/
├── ARCHITECTURE.md        # Detailed architecture documentation
├── pipe_protocol.h        # Shared IPC protocol definitions
├── plugin/
│   ├── CMakeLists.txt     # Dual-target build (plugin + server)
│   ├── plugin.h           # Plugin interface
│   ├── plugin_new.cpp     # Minimal plugin stub (~200 lines)
│   ├── plugin.cpp         # Old in-process version (deprecated)
│   ├── http_server.cpp/.h # HTTP server (deprecated)
│   ├── commands.cpp/.h    # Command handlers
│   └── debugger_state.cpp/.h  # State management
└── server/
    └── main.cpp           # HTTP server executable (separate process)
```

**Active Files** (External Process Architecture):
- `plugin_new.cpp` - Spawns server, handles Named Pipe
- `server/main.cpp` - HTTP server with Named Pipe client
- `pipe_protocol.h` - Shared protocol definitions

**Deprecated Files** (Old In-Process Architecture):
- `plugin.cpp` - Old monolithic plugin
- `http_server.cpp/.h` - In-process HTTP server (caused crashes)

### Adding New Endpoints

1. **Declare handler** in `commands.h`:
```cpp
std::string MyNewCommand(const std::string& jsonBody);
```

2. **Implement handler** in `commands.cpp`:
```cpp
std::string MyNewCommand(const std::string& jsonBody) {
    return Json::Object({
        {"success", Json::Bool(true)},
        {"result", Json::String("data")}
    });
}
```

3. **Register endpoint** in `Commands::RegisterAll()`:
```cpp
HttpServer::RegisterEndpoint("/api/my_command", MyNewCommand);
```

### Debugging the Plugin

1. Build in Debug mode: `cmake --build . --config Debug`
2. Attach Visual Studio to `x64dbg.exe`
3. Set breakpoints in plugin code
4. Plugin logs appear in x64dbg log window

### x64dbg Script API

The plugin uses x64dbg's Script API (`_scriptapi.h`):

```cpp
#include "pluginsdk/_scriptapi.h"

// Debugger control
Script::Debug::Run();
Script::Debug::Pause();
Script::Debug::StepIn();
Script::Debug::StepOver();

// Registers
duint rax = Script::Register::Get(Script::Register::RAX);
Script::Register::Set(Script::Register::RAX, value);

// Memory
Script::Memory::Read(address, buffer, size);
Script::Memory::Write(address, data, size);

// Breakpoints
Script::Breakpoint::Set(address);
Script::Breakpoint::Delete(address);

// Modules
Script::Module::GetMainModulePath(buffer);
```

## Security Considerations

- **Local only**: HTTP server binds to `127.0.0.1` (localhost)
- **No authentication**: Assumes trusted local environment
- **Input validation**: Validate all addresses and sizes
- **Memory safety**: Careful with buffer operations

## Troubleshooting

### Plugin doesn't load
- Check x64dbg log window for errors
- Ensure SDK version matches x64dbg version
- Verify DLL dependencies (use Dependency Walker)
- Make sure `x64dbg_mcp_server.exe` is in same directory

### Server process won't start
**Symptoms**: Plugin loads but no HTTP server available

**Check**:
1. Verify `x64dbg_mcp_server.exe` exists in plugins directory
2. Check x64dbg log for: `[MCP] HTTP server process started (PID: ...)`
3. Try running server manually: `x64dbg_mcp_server.exe`
4. Check Windows Event Viewer for application errors

### Pipe connection failed
**Symptoms**: Server starts but can't communicate with plugin

**Check**:
1. Only one x64dbg instance running (pipe name conflict)
2. Antivirus not blocking Named Pipes
3. x64dbg log shows: `[MCP] HTTP server connected to pipe`
4. Check for firewall blocking local IPC

### HTTP server port conflict
- Default port: 8765
- Change by passing argument to server: `x64dbg_mcp_server.exe 9000`
- Check if port is already in use: `netstat -ano | findstr 8765`

### Commands don't work
- Ensure binary is loaded in x64dbg
- Check debugger state with `/api/status`
- Review x64dbg log for exceptions
- Verify pipe communication: x64dbg log should show request messages

### Server crashes
**Good News**: x64dbg keeps running! The external process architecture isolates crashes.

**To Debug**:
1. Run server manually with console visible
2. Attach debugger to `x64dbg_mcp_server.exe` process
3. Check server console output for errors
4. Server can be restarted without restarting x64dbg

## License

See project root LICENSE file.
