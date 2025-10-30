# x64dbg MCP Bridge Plugin

Native x64dbg plugin that exposes debugger functionality via HTTP API for integration with the binary-mcp server.

## Architecture

```
MCP Server (Python) <--HTTP--> x64dbg Plugin (C++) <--SDK--> x64dbg Core
     │                              │
     │                              ├─ HTTP Server (port 8765)
     │                              ├─ Command Handlers
     │                              └─ Debugger State Manager
     │
     └─ bridge.py (HTTP client)
```

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

```bash
# Create build directory
mkdir build && cd build

# Configure CMake
cmake .. -DX64DBG_SDK_PATH="../extern/x64dbg_sdk"

# Build
cmake --build . --config Release

# Output: x64dbg_mcp.dp64 (or .dp32 for 32-bit)
```

### Install Plugin

```bash
# Option 1: Manual install
cp build/x64dbg_mcp.dp64 "C:/Program Files/x64dbg/x64/plugins/"

# Option 2: Auto-install (set environment variable)
set X64DBG_DIR=C:/Program Files/x64dbg/x64
cmake --build . --config Release
```

## API Endpoints

Base URL: `http://localhost:8765`

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

## Development

### Project Structure

```
plugin/
├── CMakeLists.txt         # Build configuration
├── plugin.cpp/.h          # Plugin entry point
├── http_server.cpp/.h     # HTTP server implementation
├── commands.cpp/.h        # Command handlers
└── debugger_state.cpp/.h  # State management
```

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

## Troubleshoints

### Plugin doesn't load
- Check x64dbg log window for errors
- Ensure SDK version matches x64dbg version
- Verify DLL dependencies (use Dependency Walker)

### HTTP server port conflict
- Default port: 8765
- Change in `plugin.cpp`: `HttpServer::Initialize(8765)`
- Check if port is already in use: `netstat -ano | findstr 8765`

### Commands don't work
- Ensure binary is loaded in x64dbg
- Check debugger state with `/api/status`
- Review x64dbg log for exceptions

## License

See project root LICENSE file.
