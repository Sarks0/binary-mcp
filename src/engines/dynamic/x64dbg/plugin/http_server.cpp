#include "http_server.h"
#include "plugin.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

// Static members
std::atomic<bool> HttpServer::s_running(false);
std::thread HttpServer::s_thread;
std::map<std::string, HttpServer::Handler> HttpServer::s_handlers;
int HttpServer::s_port = 0;

bool HttpServer::Initialize(int port) {
    s_port = port;

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LogError("WSAStartup failed");
        return false;
    }

    s_running = true;
    s_thread = std::thread(ServerThread, port);

    LogInfo("HTTP server starting on port %d", port);
    return true;
}

void HttpServer::Shutdown() {
    s_running = false;
    if (s_thread.joinable()) {
        s_thread.join();
    }
    WSACleanup();
}

void HttpServer::RegisterEndpoint(const std::string& path, Handler handler) {
    s_handlers[path] = handler;
    LogDebug("Registered endpoint: %s", path.c_str());
}

void HttpServer::ServerThread(int port) {
    // Create socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        LogError("Failed to create socket");
        return;
    }

    // Allow reuse
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    // Bind
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);

    if (bind(serverSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LogError("Bind failed on port %d", port);
        closesocket(serverSocket);
        return;
    }

    // Listen
    if (listen(serverSocket, 5) == SOCKET_ERROR) {
        LogError("Listen failed");
        closesocket(serverSocket);
        return;
    }

    LogInfo("HTTP server listening on port %d", port);

    // Accept loop
    while (s_running) {
        // Set timeout for accept
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);

        timeval timeout = { 1, 0 };  // 1 second
        int result = select(0, &readfds, nullptr, nullptr, &timeout);

        if (result <= 0) continue;

        SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) continue;

        // Receive request
        char buffer[8192];
        int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (received > 0) {
            buffer[received] = '\0';
            std::string request(buffer);

            LogDebug("Received request: %d bytes", received);

            // Handle request
            std::string response = HandleRequest(request);
            send(clientSocket, response.c_str(), (int)response.size(), 0);
        }

        closesocket(clientSocket);
    }

    closesocket(serverSocket);
    LogInfo("HTTP server stopped");
}

std::string HttpServer::HandleRequest(const std::string& request) {
    // Parse HTTP method and path
    std::istringstream iss(request);
    std::string method, path, version;
    iss >> method >> path >> version;

    LogDebug("Request: %s %s", method.c_str(), path.c_str());

    // CORS headers
    std::string corsHeaders =
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n";

    // Handle OPTIONS (CORS preflight)
    if (method == "OPTIONS") {
        return "HTTP/1.1 200 OK\r\n" + corsHeaders + "\r\n";
    }

    // Find handler
    auto it = s_handlers.find(path);
    if (it == s_handlers.end()) {
        std::string body = Json::Object({
            {"error", Json::String("Endpoint not found")},
            {"path", Json::String(path)}
        });
        return "HTTP/1.1 404 Not Found\r\n"
               "Content-Type: application/json\r\n" +
               corsHeaders +
               "Content-Length: " + std::to_string(body.size()) + "\r\n"
               "\r\n" + body;
    }

    // Parse JSON body
    std::string jsonBody = ParseJsonBody(request);

    try {
        // Call handler
        std::string responseBody = it->second(jsonBody);

        return "HTTP/1.1 200 OK\r\n"
               "Content-Type: application/json\r\n" +
               corsHeaders +
               "Content-Length: " + std::to_string(responseBody.size()) + "\r\n"
               "\r\n" + responseBody;
    }
    catch (const std::exception& e) {
        std::string errorBody = Json::Object({
            {"error", Json::String(e.what())}
        });
        return "HTTP/1.1 500 Internal Server Error\r\n"
               "Content-Type: application/json\r\n" +
               corsHeaders +
               "Content-Length: " + std::to_string(errorBody.size()) + "\r\n"
               "\r\n" + errorBody;
    }
}

std::string HttpServer::ParseJsonBody(const std::string& request) {
    size_t bodyStart = request.find("\r\n\r\n");
    if (bodyStart == std::string::npos) return "{}";
    return request.substr(bodyStart + 4);
}

// JSON helper implementations
namespace Json {
    std::string Escape(const std::string& str) {
        std::string result;
        for (char c : str) {
            switch (c) {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:   result += c; break;
            }
        }
        return result;
    }

    std::string Object(std::initializer_list<std::pair<std::string, std::string>> pairs) {
        std::string result = "{";
        bool first = true;
        for (const auto& [key, value] : pairs) {
            if (!first) result += ",";
            result += "\"" + key + "\":" + value;
            first = false;
        }
        result += "}";
        return result;
    }

    std::string Array(std::initializer_list<std::string> items) {
        std::string result = "[";
        bool first = true;
        for (const auto& item : items) {
            if (!first) result += ",";
            result += item;
            first = false;
        }
        result += "]";
        return result;
    }

    std::string String(const std::string& value) {
        return "\"" + Escape(value) + "\"";
    }

    std::string Number(long long value) {
        return std::to_string(value);
    }

    std::string Bool(bool value) {
        return value ? "true" : "false";
    }

    std::string Null() {
        return "null";
    }
}
