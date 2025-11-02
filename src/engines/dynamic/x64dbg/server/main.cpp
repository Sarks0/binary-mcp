#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <cstdarg>  // for va_list, va_start, va_end
#include "../pipe_protocol.h"

// Simple logging
void Log(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    std::cout << "[x64dbg_mcp_server] " << buffer << std::endl;
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

    // Handle GET /status
    if (method == "GET" && path == "/status") {
        // Send GET_STATE request to plugin
        std::string pipeResponse;
        if (g_pipeClient.SendRequest("{\"type\":1}", pipeResponse)) {
            return BuildHTTPResponse(200, "OK", "application/json", pipeResponse);
        } else {
            return BuildHTTPResponse(500, "Internal Server Error", "application/json",
                                   "{\"error\":\"Failed to communicate with x64dbg plugin\"}");
        }
    }

    // Handle POST requests (extract JSON body and forward to plugin)
    if (method == "POST") {
        // Find body (after \r\n\r\n)
        size_t bodyStart = request.find("\r\n\r\n");
        if (bodyStart == std::string::npos) {
            return BuildHTTPResponse(400, "Bad Request", "text/plain", "Missing request body");
        }

        std::string body = request.substr(bodyStart + 4);

        // Forward to plugin via Named Pipe
        std::string pipeResponse;
        if (g_pipeClient.SendRequest(body, pipeResponse)) {
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

        SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) {
            Log("Accept failed: %d", WSAGetLastError());
            continue;
        }

        // Read HTTP request
        char buffer[8192];
        int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::string request(buffer, bytesRead);

            // Handle request and send response
            std::string response = HandleHTTPRequest(request);
            send(clientSocket, response.c_str(), (int)response.size(), 0);
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

    // Start HTTP server
    bool success = StartHTTPServer(port);

    // Cleanup
    g_pipeClient.Disconnect();
    WSACleanup();

    return success ? 0 : 1;
}
