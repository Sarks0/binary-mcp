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

// HTTP Server stub (minimal for now - we'll add full implementation later)
bool StartHTTPServer(int port) {
    Log("HTTP server would start on port %d", port);
    Log("(Full HTTP server implementation to be added)");

    // For now, just keep the process alive
    Log("Press Ctrl+C to stop server");

    while (true) {
        Sleep(1000);

        // Periodically ping the plugin to keep connection alive
        std::string response;
        if (g_pipeClient.SendRequest("{\"type\":99}", response)) {
            // Successfully communicated with plugin
        } else {
            Log("Lost connection to plugin, exiting...");
            return false;
        }
    }

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
