#pragma once

#include <string>
#include <cstdint>  // for uint32_t
#include <cstddef>  // for size_t

// Shared protocol definitions for Named Pipe communication
// between x64dbg plugin (server) and HTTP server process (client)

namespace Protocol {
    // Pipe name (must match on both sides)
    constexpr const char* PIPE_NAME = "\\\\.\\pipe\\x64dbg_mcp";

    // Message types from HTTP server to plugin
    enum class RequestType : uint32_t {
        GET_STATE = 1,          // Get debugger state
        EXECUTE_COMMAND = 2,    // Execute x64dbg command
        READ_MEMORY = 3,        // Read process memory
        WRITE_MEMORY = 4,       // Write process memory
        GET_REGISTERS = 5,      // Get register values
        SET_BREAKPOINT = 6,     // Set breakpoint
        PING = 99,              // Health check
        SHUTDOWN = 100          // Server shutting down
    };

    // Response status codes
    enum class Status : uint32_t {
        SUCCESS = 0,
        FAILED = 1,             // Renamed from ERROR to avoid Windows macro conflict
        NOT_DEBUGGING = 2,
        INVALID_REQUEST = 3
    };

    // Maximum message size (1MB)
    constexpr size_t MAX_MESSAGE_SIZE = 1024 * 1024;

    // Simple message format (JSON over pipe)
    // Format: [4 bytes length][JSON data]
    //
    // Request JSON:
    // {
    //   "type": <RequestType>,
    //   "data": { ... request-specific data ... }
    // }
    //
    // Response JSON:
    // {
    //   "status": <Status>,
    //   "data": { ... response data ... }
    // }
}
