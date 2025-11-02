#pragma once

#include <string>
#include <functional>
#include <map>
#include <atomic>
#include <Windows.h>

// Simple HTTP server for MCP bridge API
class HttpServer {
public:
    using Handler = std::function<std::string(const std::string& body)>;

    static bool Initialize(int port);
    static void Shutdown();
    static void RegisterEndpoint(const std::string& path, Handler handler);
    static std::string GetAuthToken();  // Get current auth token

private:
    static DWORD WINAPI ServerThread(LPVOID lpParam);  // Windows native thread
    static std::string HandleRequest(const std::string& request);
    static std::string ParseJsonBody(const std::string& request);
    static std::string GenerateAuthToken();  // Generate secure random token
    static bool ValidateAuthToken(const std::string& request);  // Validate Authorization header
    static std::string ExtractHeader(const std::string& request, const std::string& header);
    static void SaveTokenToFile(const std::string& token);  // Save token for client

    // CRITICAL: Use pointers instead of static objects
    // Static objects initialize during DLL_PROCESS_ATTACH which is too early and unsafe
    // Pointers are just NULL until we allocate them in Initialize()
    static std::atomic<bool>* s_running;
    static HANDLE s_thread;  // Windows native thread handle (not std::thread)
    static std::map<std::string, Handler>* s_handlers;
    static int s_port;
    static std::string* s_auth_token;  // Authentication token
};

// JSON helper functions
namespace Json {
    std::string Escape(const std::string& str);
    std::string Object(std::initializer_list<std::pair<std::string, std::string>> pairs);
    std::string Array(std::initializer_list<std::string> items);
    std::string String(const std::string& value);
    std::string Number(long long value);
    std::string Bool(bool value);
    std::string Null();
}
