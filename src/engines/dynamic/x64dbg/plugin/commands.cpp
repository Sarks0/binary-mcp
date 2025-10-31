#include "commands.h"
#include "http_server.h"
#include "debugger_state.h"
#include "plugin.h"
#include <sstream>
#include <iomanip>

// TODO: Script API integration needs proper SDK headers
// For now, stub out JSON helpers
static std::string Object(std::initializer_list<std::pair<const char*, std::string>> items) {
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (const auto& item : items) {
        if (!first) oss << ",";
        oss << "\"" << item.first << "\":" << item.second;
        first = false;
    }
    oss << "}";
    return oss.str();
}

static std::string Bool(bool value) {
    return value ? "true" : "false";
}

static std::string String(const std::string& value) {
    return "\"" + value + "\"";
}

static std::string Array(std::initializer_list<std::string> items) {
    std::ostringstream oss;
    oss << "[";
    bool first = true;
    for (const auto& item : items) {
        if (!first) oss << ",";
        oss << item;
        first = false;
    }
    oss << "]";
    return oss.str();
}

namespace Commands {

void RegisterAll() {
    HttpServer::RegisterEndpoint("/api/status", Status);
    HttpServer::RegisterEndpoint("/api/load", LoadBinary);
    HttpServer::RegisterEndpoint("/api/run", Run);
    HttpServer::RegisterEndpoint("/api/pause", Pause);
    HttpServer::RegisterEndpoint("/api/step_into", StepInto);
    HttpServer::RegisterEndpoint("/api/step_over", StepOver);
    HttpServer::RegisterEndpoint("/api/step_out", StepOut);

    HttpServer::RegisterEndpoint("/api/breakpoint/set", SetBreakpoint);
    HttpServer::RegisterEndpoint("/api/breakpoint/delete", DeleteBreakpoint);
    HttpServer::RegisterEndpoint("/api/breakpoint/list", ListBreakpoints);

    HttpServer::RegisterEndpoint("/api/registers", GetRegisters);
    HttpServer::RegisterEndpoint("/api/stack", GetStack);
    HttpServer::RegisterEndpoint("/api/modules", GetModules);
    HttpServer::RegisterEndpoint("/api/threads", GetThreads);

    HttpServer::RegisterEndpoint("/api/memory/read", ReadMemory);
    HttpServer::RegisterEndpoint("/api/memory/write", WriteMemory);
    HttpServer::RegisterEndpoint("/api/disassemble", Disassemble);

    LogInfo("Registered %d API endpoints", 16);
}

std::string Status(const std::string& jsonBody) {
    auto state = DebuggerState::Get();

    return Object({
        {"success", Bool(true)},
        {"state", String(state.state)},
        {"binary_loaded", Bool(state.binaryLoaded)},
        {"binary_path", String(state.binaryPath)},
        {"is_running", Bool(state.isRunning)},
        {"current_address", String(state.currentAddress)}
    });
}

std::string LoadBinary(const std::string& jsonBody) {
    return Object({
        {"success", Bool(false)},
        {"error", String("Binary loading requires Script API - not yet implemented")}
    });
}

std::string Run(const std::string& jsonBody) {
    // TODO: Implement with proper x64dbg API calls
    return Object({
        {"success", Bool(false)},
        {"error", String("Debug::Run requires Script API - not yet implemented")}
    });
}

std::string Pause(const std::string& jsonBody) {
    // TODO: Implement with proper x64dbg API calls
    return Object({
        {"success", Bool(false)},
        {"error", String("Debug::Pause requires Script API - not yet implemented")}
    });
}

std::string StepInto(const std::string& jsonBody) {
    // TODO: Implement with proper x64dbg API calls
    return Object({
        {"success", Bool(false)},
        {"error", String("Debug::StepIn requires Script API - not yet implemented")}
    });
}

std::string StepOver(const std::string& jsonBody) {
    // TODO: Implement with proper x64dbg API calls
    return Object({
        {"success", Bool(false)},
        {"error", String("Debug::StepOver requires Script API - not yet implemented")}
    });
}

std::string StepOut(const std::string& jsonBody) {
    // TODO: Implement with proper x64dbg API calls
    return Object({
        {"success", Bool(false)},
        {"error", String("Debug::StepOut requires Script API - not yet implemented")}
    });
}

std::string SetBreakpoint(const std::string& jsonBody) {
    return Object({
        {"success", Bool(false)},
        {"error", String("Not yet implemented")}
    });
}

std::string DeleteBreakpoint(const std::string& jsonBody) {
    return Object({
        {"success", Bool(false)},
        {"error", String("Not yet implemented")}
    });
}

std::string ListBreakpoints(const std::string& jsonBody) {
    return Object({
        {"success", Bool(true)},
        {"breakpoints", Array({})}
    });
}

std::string GetRegisters(const std::string& jsonBody) {
    // TODO: Implement with proper x64dbg API calls
    return Object({
        {"success", Bool(false)},
        {"error", String("Register::Get requires Script API - not yet implemented")}
    });
}

std::string GetStack(const std::string& jsonBody) {
    return Object({
        {"success", Bool(false)},
        {"error", String("Not yet implemented")}
    });
}

std::string GetModules(const std::string& jsonBody) {
    return Object({
        {"success", Bool(false)},
        {"error", String("Not yet implemented")}
    });
}

std::string GetThreads(const std::string& jsonBody) {
    return Object({
        {"success", Bool(false)},
        {"error", String("Not yet implemented")}
    });
}

std::string ReadMemory(const std::string& jsonBody) {
    return Object({
        {"success", Bool(false)},
        {"error", String("Not yet implemented")}
    });
}

std::string WriteMemory(const std::string& jsonBody) {
    return Object({
        {"success", Bool(false)},
        {"error", String("Not yet implemented")}
    });
}

std::string Disassemble(const std::string& jsonBody) {
    return Object({
        {"success", Bool(false)},
        {"error", String("Not yet implemented")}
    });
}

}  // namespace Commands
