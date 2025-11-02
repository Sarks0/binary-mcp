#include "http_server.h"
#include "plugin.h"
#include <sstream>
#include <algorithm>
#include <fstream>
#include <random>
#include <iomanip>
#include <Windows.h>
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

// Static members
std::atomic<bool> HttpServer::s_running(false);
std::thread HttpServer::s_thread;
std::map<std::string, HttpServer::Handler> HttpServer::s_handlers;
int HttpServer::s_port = 0;
std::string HttpServer::s_auth_token;

// Generate cryptographically secure random authentication token
std::string HttpServer::GenerateAuthToken() {
    HCRYPTPROV hProvider = 0;
    const size_t TOKEN_BYTES = 32;  // 256 bits
    unsigned char randomBytes[TOKEN_BYTES];

    // Use Windows Crypto API for secure random generation
    if (!CryptAcquireContext(&hProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        LogError("CryptAcquireContext failed");
        // Fallback to less secure method
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (size_t i = 0; i < TOKEN_BYTES; i++) {
            randomBytes[i] = static_cast<unsigned char>(dis(gen));
        }
    } else {
        if (!CryptGenRandom(hProvider, TOKEN_BYTES, randomBytes)) {
            LogError("CryptGenRandom failed");
            CryptReleaseContext(hProvider, 0);
            // Fallback
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            for (size_t i = 0; i < TOKEN_BYTES; i++) {
                randomBytes[i] = static_cast<unsigned char>(dis(gen));
            }
        } else {
            CryptReleaseContext(hProvider, 0);
        }
    }

    // Convert to hex string
    std::ostringstream oss;
    for (size_t i = 0; i < TOKEN_BYTES; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(randomBytes[i]);
    }

    return oss.str();
}

// Save authentication token to file for Python bridge to read
void HttpServer::SaveTokenToFile(const std::string& token) {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) == 0) {
        LogError("Failed to get temp path");
        return;
    }

    std::string tokenFile = std::string(tempPath) + "x64dbg_mcp_token.txt";
    std::ofstream file(tokenFile, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        LogError("Failed to create token file: %s", tokenFile.c_str());
        return;
    }

    file << token;
    file.close();

    LogInfo("Authentication token saved to: %s", tokenFile.c_str());
}

// Extract HTTP header value
std::string HttpServer::ExtractHeader(const std::string& request, const std::string& header) {
    std::string headerLower = header;
    std::transform(headerLower.begin(), headerLower.end(), headerLower.begin(), ::tolower);

    std::istringstream iss(request);
    std::string line;

    // Skip request line
    std::getline(iss, line);

    // Parse headers
    while (std::getline(iss, line)) {
        if (line == "\r" || line.empty()) break;

        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);

            if (key == headerLower) {
                std::string value = line.substr(colonPos + 1);
                // Trim whitespace
                value.erase(0, value.find_first_not_of(" \t\r\n"));
                value.erase(value.find_last_not_of(" \t\r\n") + 1);
                return value;
            }
        }
    }

    return "";
}

// Validate authentication token (constant-time comparison)
bool HttpServer::ValidateAuthToken(const std::string& request) {
    std::string authHeader = ExtractHeader(request, "Authorization");
    if (authHeader.empty()) {
        LogDebug("Missing Authorization header");
        return false;
    }

    // Expected format: "Bearer <token>"
    const std::string bearerPrefix = "Bearer ";
    if (authHeader.find(bearerPrefix) != 0) {
        LogDebug("Invalid Authorization format");
        return false;
    }

    std::string providedToken = authHeader.substr(bearerPrefix.length());

    // Constant-time comparison to prevent timing attacks
    if (providedToken.length() != s_auth_token.length()) {
        return false;
    }

    volatile int result = 0;
    for (size_t i = 0; i < providedToken.length(); i++) {
        result |= providedToken[i] ^ s_auth_token[i];
    }

    return result == 0;
}

// Get current authentication token
std::string HttpServer::GetAuthToken() {
    return s_auth_token;
}

bool HttpServer::Initialize(int port) {
    s_port = port;

    try {
        // Generate and save authentication token
        s_auth_token = GenerateAuthToken();
        SaveTokenToFile(s_auth_token);
        LogInfo("Generated authentication token (%zu chars)", s_auth_token.length());

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
    catch (const std::exception& e) {
        LogError("Failed to initialize HTTP server: %s", e.what());
        return false;
    }
    catch (...) {
        LogError("Failed to initialize HTTP server: unknown error");
        return false;
    }
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
    try {
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

        // Receive request (SECURITY: Use dynamic allocation to prevent buffer overflow)
        const size_t INITIAL_BUFFER_SIZE = 8192;
        const size_t MAX_REQUEST_SIZE = 1024 * 1024;  // 1MB max
        std::vector<char> buffer(INITIAL_BUFFER_SIZE);
        std::string request;
        size_t totalReceived = 0;

        while (totalReceived < MAX_REQUEST_SIZE) {
            int received = recv(clientSocket, buffer.data(), buffer.size(), 0);
            if (received <= 0) break;

            request.append(buffer.data(), received);
            totalReceived += received;

            // Check if we have complete HTTP request (ends with \r\n\r\n)
            if (request.find("\r\n\r\n") != std::string::npos) {
                break;
            }
        }

        if (!request.empty()) {
            LogDebug("Received request: %zu bytes", totalReceived);

            // Handle request
            std::string response = HandleRequest(request);
            send(clientSocket, response.c_str(), (int)response.size(), 0);
        }

            closesocket(clientSocket);
        }

        closesocket(serverSocket);
        LogInfo("HTTP server stopped");
    }
    catch (const std::exception& e) {
        LogError("HTTP server thread crashed: %s", e.what());
    }
    catch (...) {
        LogError("HTTP server thread crashed: unknown error");
    }
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
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";

    // Handle OPTIONS (CORS preflight)
    if (method == "OPTIONS") {
        return "HTTP/1.1 200 OK\r\n" + corsHeaders + "\r\n";
    }

    // Validate authentication token (SECURITY: Prevent unauthorized access)
    if (!ValidateAuthToken(request)) {
        std::string body = Json::Object({
            {"error", Json::String("Unauthorized - Invalid or missing authentication token")},
            {"hint", Json::String("Include 'Authorization: Bearer <token>' header")}
        });
        return "HTTP/1.1 401 Unauthorized\r\n"
               "Content-Type: application/json\r\n" +
               corsHeaders +
               "WWW-Authenticate: Bearer\r\n"
               "Content-Length: " + std::to_string(body.size()) + "\r\n"
               "\r\n" + body;
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
