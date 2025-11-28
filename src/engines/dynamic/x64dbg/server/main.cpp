#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <cstdarg>  // for va_list, va_start, va_end
#include <fstream>
#include "../pipe_protocol.h"

// Global authentication token
static std::string g_authToken;

// Simple logging
void Log(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    std::cout << "[x64dbg_mcp_server] " << buffer << std::endl;
}

// Constant-time string comparison to prevent timing attacks
bool SecureCompare(const char* a, const char* b, size_t len) {
    volatile unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

// Load authentication token from file
bool LoadAuthToken() {
    // Get temp directory
    char tempPath[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tempPath)) {
        Log("Failed to get temp path: %d", GetLastError());
        return false;
    }

    std::string tokenPath = std::string(tempPath) + "x64dbg_mcp_token.txt";
    Log("Loading auth token from: %s", tokenPath.c_str());

    // Read token from file
    std::ifstream file(tokenPath);
    if (!file.is_open()) {
        Log("Failed to open token file - plugin may not be loaded");
        return false;
    }

    std::getline(file, g_authToken);
    file.close();

    if (g_authToken.empty()) {
        Log("Token file is empty");
        return false;
    }

    Log("Auth token loaded (%zu bytes)", g_authToken.size());
    return true;
}

// Validate Authorization header
bool ValidateAuthHeader(const std::string& request) {
    // If no token configured, skip validation (for backwards compatibility)
    if (g_authToken.empty()) {
        return true;
    }

    // Find Authorization header
    size_t authPos = request.find("Authorization:");
    if (authPos == std::string::npos) {
        authPos = request.find("authorization:");  // case-insensitive
    }

    if (authPos == std::string::npos) {
        Log("Missing Authorization header");
        return false;
    }

    // Extract token from "Authorization: Bearer <token>"
    size_t bearerPos = request.find("Bearer ", authPos);
    if (bearerPos == std::string::npos) {
        Log("Invalid Authorization format (expected 'Bearer <token>')");
        return false;
    }

    bearerPos += 7;  // Skip "Bearer "
    size_t tokenEnd = request.find('\r', bearerPos);
    if (tokenEnd == std::string::npos) {
        tokenEnd = request.find('\n', bearerPos);
    }

    std::string providedToken = request.substr(bearerPos, tokenEnd - bearerPos);

    // Constant-time comparison to prevent timing attacks
    if (providedToken.length() != g_authToken.length()) {
        Log("Invalid token (wrong length)");
        return false;
    }

    if (!SecureCompare(providedToken.c_str(), g_authToken.c_str(), g_authToken.length())) {
        Log("Invalid token (mismatch)");
        return false;
    }

    return true;
}

// Named Pipe client to communicate with plugin
class PipeClient {
private:
    HANDLE m_pipe = INVALID_HANDLE_VALUE;
    std::atomic<bool> m_connected{false};

public:
    bool Connect() {
        Log("Connecting to plugin pipe: %s", Protocol::PIPE_NAME);

        // Try to connect to the named pipe (plugin is the server)
        for (int attempts = 0; attempts < 10; attempts++) {
            m_pipe = CreateFileA(
                Protocol::PIPE_NAME,
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr
            );

            if (m_pipe != INVALID_HANDLE_VALUE) {
                m_connected = true;
                Log("Connected to plugin pipe");
                return true;
            }

            if (GetLastError() != ERROR_PIPE_BUSY) {
                Log("Failed to connect to pipe: %d", GetLastError());
                return false;
            }

            Log("Pipe busy, retrying... (attempt %d/10)", attempts + 1);
            Sleep(500);  // Wait before retry
        }

        Log("Failed to connect: pipe busy");
        return false;
    }

    bool SendRequest(const std::string& jsonRequest, std::string& jsonResponse) {
        if (!m_connected || m_pipe == INVALID_HANDLE_VALUE) {
            return false;
        }

        // Send length prefix + JSON
        uint32_t length = static_cast<uint32_t>(jsonRequest.size());
        DWORD bytesWritten = 0;

        if (!WriteFile(m_pipe, &length, sizeof(length), &bytesWritten, nullptr)) {
            Log("Failed to write length: %d", GetLastError());
            return false;
        }

        if (!WriteFile(m_pipe, jsonRequest.c_str(), length, &bytesWritten, nullptr)) {
            Log("Failed to write request: %d", GetLastError());
            return false;
        }

        // Read response length
        uint32_t responseLength = 0;
        DWORD bytesRead = 0;

        if (!ReadFile(m_pipe, &responseLength, sizeof(responseLength), &bytesRead, nullptr)) {
            Log("Failed to read response length: %d", GetLastError());
            return false;
        }

        if (responseLength > Protocol::MAX_MESSAGE_SIZE) {
            Log("Response too large: %u bytes", responseLength);
            return false;
        }

        // Read response data
        std::vector<char> buffer(responseLength);
        if (!ReadFile(m_pipe, buffer.data(), responseLength, &bytesRead, nullptr)) {
            Log("Failed to read response: %d", GetLastError());
            return false;
        }

        jsonResponse = std::string(buffer.data(), responseLength);
        return true;
    }

    void Disconnect() {
        if (m_pipe != INVALID_HANDLE_VALUE) {
            CloseHandle(m_pipe);
            m_pipe = INVALID_HANDLE_VALUE;
        }
        m_connected = false;
    }

    ~PipeClient() {
        Disconnect();
    }
};

// Global pipe client
static PipeClient g_pipeClient;

// Simple HTTP response builder
std::string BuildHTTPResponse(int statusCode, const std::string& statusText,
                               const std::string& contentType, const std::string& body) {
    std::string response = "HTTP/1.1 " + std::to_string(statusCode) + " " + statusText + "\r\n";
    response += "Content-Type: " + contentType + "\r\n";
    response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    response += "Access-Control-Allow-Origin: *\r\n";
    response += "Connection: close\r\n";
    response += "\r\n";
    response += body;
    return response;
}

// HTTP request handler
std::string HandleHTTPRequest(const std::string& request) {
    // Parse HTTP method and path
    size_t methodEnd = request.find(' ');
    if (methodEnd == std::string::npos) {
        return BuildHTTPResponse(400, "Bad Request", "text/plain", "Invalid HTTP request");
    }

    std::string method = request.substr(0, methodEnd);
    size_t pathEnd = request.find(' ', methodEnd + 1);
    if (pathEnd == std::string::npos) {
        return BuildHTTPResponse(400, "Bad Request", "text/plain", "Invalid HTTP request");
    }

    std::string path = request.substr(methodEnd + 1, pathEnd - methodEnd - 1);

    Log("HTTP %s %s", method.c_str(), path.c_str());

    // Validate authentication (except for OPTIONS preflight)
    if (method != "OPTIONS" && !ValidateAuthHeader(request)) {
        Log("Authentication failed for %s %s", method.c_str(), path.c_str());
        return BuildHTTPResponse(401, "Unauthorized", "application/json",
                                "{\"error\":\"Invalid or missing authentication token\"}");
    }

    // Handle OPTIONS (CORS preflight)
    if (method == "OPTIONS") {
        std::string response = "HTTP/1.1 200 OK\r\n";
        response += "Access-Control-Allow-Origin: *\r\n";
        response += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
        response += "Access-Control-Allow-Headers: Content-Type\r\n";
        response += "Connection: close\r\n";
        response += "\r\n";
        return response;
    }

    // Handle GET /health
    if (method == "GET" && path == "/health") {
        return BuildHTTPResponse(200, "OK", "application/json",
                                "{\"status\":\"ok\",\"message\":\"x64dbg MCP server running\"}");
    }

    // Extract request body for POST requests
    std::string requestBody = "";
    if (method == "POST") {
        size_t bodyStart = request.find("\r\n\r\n");
        if (bodyStart != std::string::npos) {
            requestBody = request.substr(bodyStart + 4);
        }
    }

    // Map endpoint URL to request type number
    int requestType = -1;

    // P0 Handlers (Implemented)
    if (path == "/api/status") {
        requestType = 1;  // GET_STATE
    } else if (path == "/api/registers") {
        requestType = 5;  // GET_REGISTERS
    } else if (path == "/api/step_into") {
        requestType = 10;  // STEP_INTO
    } else if (path == "/api/step_over") {
        requestType = 11;  // STEP_OVER
    } else if (path == "/api/step_out") {
        requestType = 12;  // STEP_OUT
    } else if (path == "/api/memory/read") {
        requestType = 3;  // READ_MEMORY
    } else if (path == "/api/breakpoint/set") {
        requestType = 20;  // SET_BREAKPOINT

    // Core Functionality (Not Yet Implemented)
    } else if (path == "/api/load") {
        requestType = 2;  // LOAD_BINARY
    } else if (path == "/api/run") {
        requestType = 8;  // RUN
    } else if (path == "/api/pause") {
        requestType = 9;  // PAUSE
    } else if (path == "/api/memory/write") {
        requestType = 4;  // WRITE_MEMORY
    } else if (path == "/api/register/set") {
        requestType = 6;  // SET_REGISTER

    // Breakpoints (Not Yet Implemented)
    } else if (path == "/api/breakpoint/delete") {
        requestType = 21;  // DELETE_BREAKPOINT
    } else if (path == "/api/breakpoint/list") {
        requestType = 22;  // LIST_BREAKPOINTS
    } else if (path == "/api/breakpoint/hardware") {
        requestType = 30;  // SET_HARDWARE_BREAKPOINT
    } else if (path == "/api/breakpoint/memory") {
        requestType = 31;  // SET_MEMORY_BREAKPOINT
    } else if (path == "/api/breakpoint/memory/delete") {
        requestType = 32;  // DELETE_MEMORY_BREAKPOINT

    // Analysis Tools (Not Yet Implemented)
    } else if (path == "/api/disassemble") {
        requestType = 7;  // DISASSEMBLE
    } else if (path == "/api/stack") {
        requestType = 13;  // GET_STACK
    } else if (path == "/api/modules") {
        requestType = 14;  // GET_MODULES
    } else if (path == "/api/threads") {
        requestType = 15;  // GET_THREADS
    } else if (path == "/api/instruction") {
        requestType = 40;  // GET_INSTRUCTION
    } else if (path == "/api/evaluate") {
        requestType = 41;  // EVALUATE_EXPRESSION

    // Memory Tools (Not Yet Implemented)
    } else if (path == "/api/memory/map") {
        requestType = 50;  // GET_MEMORY_MAP
    } else if (path == "/api/memory/info") {
        requestType = 51;  // GET_MEMORY_INFO
    } else if (path == "/api/memory/dump") {
        requestType = 52;  // DUMP_MEMORY
    } else if (path == "/api/memory/search") {
        requestType = 53;  // SEARCH_MEMORY

    // Module Tools (Not Yet Implemented)
    } else if (path == "/api/module/imports") {
        requestType = 60;  // GET_MODULE_IMPORTS
    } else if (path == "/api/module/exports") {
        requestType = 61;  // GET_MODULE_EXPORTS

    // Comments (Not Yet Implemented)
    } else if (path == "/api/comment/set") {
        requestType = 70;  // SET_COMMENT
    } else if (path == "/api/comment/get") {
        requestType = 71;  // GET_COMMENT

    // Advanced Control (Not Yet Implemented)
    } else if (path == "/api/skip") {
        requestType = 80;  // SKIP_INSTRUCTION
    } else if (path == "/api/run_until_return") {
        requestType = 81;  // RUN_UNTIL_RETURN
    } else if (path == "/api/hide_debugger") {
        requestType = 90;  // HIDE_DEBUGGER

    // Wait/Synchronization (Phase 1)
    } else if (path == "/api/wait/paused") {
        requestType = 91;  // WAIT_PAUSED
    } else if (path == "/api/wait/running") {
        requestType = 92;  // WAIT_RUNNING
    } else if (path == "/api/wait/debugging") {
        requestType = 93;  // WAIT_DEBUGGING

    // Symbol resolution
    } else if (path == "/api/resolve") {
        requestType = 95;  // RESOLVE_SYMBOL

    // Events
    } else if (path == "/api/events") {
        requestType = 100;  // GET_EVENTS
    } else if (path == "/api/events/clear") {
        requestType = 101;  // CLEAR_EVENTS
    } else if (path == "/api/events/status") {
        requestType = 102;  // GET_EVENT_STATUS

    // Memory Allocation (Phase 3)
    } else if (path == "/api/memory/alloc") {
        requestType = 110;  // VIRT_ALLOC
    } else if (path == "/api/memory/free") {
        requestType = 111;  // VIRT_FREE
    } else if (path == "/api/memory/protect") {
        requestType = 112;  // VIRT_PROTECT
    } else if (path == "/api/memory/set") {
        requestType = 113;  // MEM_SET
    } else if (path == "/api/memory/check") {
        requestType = 114;  // CHECK_VALID_PTR

    // Enhanced Breakpoints (Phase 3)
    } else if (path == "/api/breakpoint/toggle") {
        requestType = 120;  // TOGGLE_BREAKPOINT
    } else if (path == "/api/breakpoint/hardware/delete") {
        requestType = 121;  // DELETE_HARDWARE_BREAKPOINT
    } else if (path == "/api/breakpoint/hardware/toggle") {
        requestType = 122;  // TOGGLE_HARDWARE_BREAKPOINT
    } else if (path == "/api/breakpoint/memory/toggle") {
        requestType = 123;  // TOGGLE_MEMORY_BREAKPOINT
    } else if (path == "/api/breakpoint/list/all") {
        requestType = 124;  // LIST_ALL_BREAKPOINTS

    // Phase 4: Tracing
    } else if (path == "/api/trace/start") {
        requestType = 130;  // START_TRACE
    } else if (path == "/api/trace/stop") {
        requestType = 131;  // STOP_TRACE
    } else if (path == "/api/trace/data") {
        requestType = 132;  // GET_TRACE_DATA
    } else if (path == "/api/trace/clear") {
        requestType = 133;  // CLEAR_TRACE
    } else if (path == "/api/api_breakpoint") {
        requestType = 134;  // SET_API_BREAKPOINT
    } else if (path == "/api/api_log") {
        requestType = 135;  // GET_API_LOG
    } else if (path == "/api/api_log/clear") {
        requestType = 136;  // CLEAR_API_LOG

    // Phase 4: String & Pattern Search
    } else if (path == "/api/strings") {
        requestType = 140;  // FIND_STRINGS
    } else if (path == "/api/pattern") {
        requestType = 141;  // PATTERN_SCAN
    } else if (path == "/api/xor") {
        requestType = 142;  // XOR_DECRYPT

    // Phase 4: References & Analysis
    } else if (path == "/api/references") {
        requestType = 145;  // FIND_REFERENCES
    } else if (path == "/api/callstack/detailed") {
        requestType = 146;  // GET_CALL_STACK_DETAILED

    // Phase 5: Anti-Debug Bypass
    } else if (path == "/api/antidebug/peb") {
        requestType = 150;  // HIDE_DEBUG_PEB
    } else if (path == "/api/antidebug/full") {
        requestType = 151;  // HIDE_DEBUG_FULL
    } else if (path == "/api/antidebug/status") {
        requestType = 152;  // GET_ANTI_DEBUG_STATUS
    } else if (path == "/api/antidebug/patch") {
        requestType = 153;  // PATCH_DBG_CHECK

    // Phase 6: Code Coverage
    } else if (path == "/api/coverage/start") {
        requestType = 160;  // START_COVERAGE
    } else if (path == "/api/coverage/stop") {
        requestType = 161;  // STOP_COVERAGE
    } else if (path == "/api/coverage/data") {
        requestType = 162;  // GET_COVERAGE_DATA
    } else if (path == "/api/coverage/clear") {
        requestType = 163;  // CLEAR_COVERAGE
    } else if (path == "/api/coverage/stats") {
        requestType = 164;  // GET_COVERAGE_STATS
    } else if (path == "/api/coverage/export") {
        requestType = 165;  // EXPORT_COVERAGE
    }

    // If we have a valid endpoint, build request and forward to plugin
    if (requestType != -1) {
        // Build JSON request with type field
        std::string pluginRequest;
        if (requestBody.empty() || requestBody == "{}" || requestBody == "{}") {
            // No body or empty body - just send type
            pluginRequest = "{\"type\":" + std::to_string(requestType) + "}";
        } else {
            // Merge type into existing JSON body
            // Simple approach: inject "type" at the beginning
            size_t firstBrace = requestBody.find('{');
            if (firstBrace != std::string::npos) {
                pluginRequest = "{\"type\":" + std::to_string(requestType) + ",";
                pluginRequest += requestBody.substr(firstBrace + 1);
            } else {
                pluginRequest = "{\"type\":" + std::to_string(requestType) + "}";
            }
        }

        // Forward to plugin via Named Pipe
        std::string pipeResponse;
        if (g_pipeClient.SendRequest(pluginRequest, pipeResponse)) {
            return BuildHTTPResponse(200, "OK", "application/json", pipeResponse);
        } else {
            return BuildHTTPResponse(500, "Internal Server Error", "application/json",
                                   "{\"error\":\"Failed to communicate with x64dbg plugin\"}");
        }
    }

    return BuildHTTPResponse(404, "Not Found", "text/plain", "Endpoint not found");
}

// HTTP Server implementation
bool StartHTTPServer(int port) {
    Log("Starting HTTP server on port %d...", port);

    // Create listening socket
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        Log("Failed to create socket: %d", WSAGetLastError());
        return false;
    }

    // Allow port reuse
    int optval = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));

    // Set socket to non-blocking mode for accept() timeout
    u_long mode = 1;
    ioctlsocket(listenSocket, FIONBIO, &mode);

    // Bind to port
    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        Log("Failed to bind to port %d: %d", port, WSAGetLastError());
        closesocket(listenSocket);
        return false;
    }

    // Listen for connections
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        Log("Failed to listen: %d", WSAGetLastError());
        closesocket(listenSocket);
        return false;
    }

    Log("HTTP server listening on http://127.0.0.1:%d", port);
    Log("Press Ctrl+C to stop server");

    // Accept and handle connections
    while (true) {
        sockaddr_in clientAddr = {};
        int clientAddrLen = sizeof(clientAddr);

        // Use select() for timeout on accept
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listenSocket, &readfds);

        timeval timeout = {1, 0};  // 1 second timeout
        int selectResult = select(0, &readfds, nullptr, nullptr, &timeout);

        if (selectResult == SOCKET_ERROR) {
            Log("Select failed: %d", WSAGetLastError());
            break;
        }

        if (selectResult == 0) {
            // Timeout - periodically check if plugin is still alive
            std::string response;
            if (!g_pipeClient.SendRequest("{\"type\":99}", response)) {
                Log("Lost connection to plugin, exiting...");
                break;
            }
            continue;
        }

        // Accept new connection
        SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                Log("Accept failed: %d", error);
            }
            continue;
        }

        // Set client socket to blocking mode
        mode = 0;
        ioctlsocket(clientSocket, FIONBIO, &mode);

        // Set receive timeout (5 seconds)
        int recvTimeout = 5000;
        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recvTimeout, sizeof(recvTimeout));

        // Set send timeout (5 seconds)
        int sendTimeout = 5000;
        setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sendTimeout, sizeof(sendTimeout));

        // Read HTTP request
        char buffer[8192];
        int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::string request(buffer, bytesRead);

            // Handle request and send response
            std::string response = HandleHTTPRequest(request);
            send(clientSocket, response.c_str(), (int)response.size(), 0);
        } else if (bytesRead == SOCKET_ERROR) {
            Log("Recv failed: %d", WSAGetLastError());
        }

        closesocket(clientSocket);
    }

    closesocket(listenSocket);
    return true;
}

int main(int argc, char* argv[]) {
    Log("x64dbg MCP Server starting...");

    // Parse command line arguments
    int port = 8765;  // Default port
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        Log("WSAStartup failed");
        return 1;
    }

    // Connect to plugin via Named Pipe
    if (!g_pipeClient.Connect()) {
        Log("Failed to connect to plugin - make sure x64dbg is running with plugin loaded");
        WSACleanup();
        return 1;
    }

    // Load authentication token
    if (!LoadAuthToken()) {
        Log("Warning: Could not load auth token - authentication disabled");
        Log("This is insecure! Make sure the x64dbg plugin is loaded.");
    }

    // Start HTTP server
    bool success = StartHTTPServer(port);

    // Cleanup
    g_pipeClient.Disconnect();
    WSACleanup();

    return success ? 0 : 1;
}
