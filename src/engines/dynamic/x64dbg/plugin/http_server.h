#pragma once

#include <string>
#include <functional>
#include <map>
#include <thread>
#include <atomic>

// Simple HTTP server for MCP bridge API
class HttpServer {
public:
    using Handler = std::function<std::string(const std::string& body)>;

    static bool Initialize(int port);
    static void Shutdown();
    static void RegisterEndpoint(const std::string& path, Handler handler);

private:
    static void ServerThread(int port);
    static std::string HandleRequest(const std::string& request);
    static std::string ParseJsonBody(const std::string& request);

    static std::atomic<bool> s_running;
    static std::thread s_thread;
    static std::map<std::string, Handler> s_handlers;
    static int s_port;
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
