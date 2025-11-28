#include "commands.h"
#include "http_server.h"
#include "debugger_state.h"
#include "plugin.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

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

// Simple JSON value extractor (finds "key": value pattern)
static int ParseJsonInt(const std::string& json, const std::string& key, int defaultValue) {
    std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return defaultValue;

    // Skip past the key and colon
    pos = json.find(':', pos);
    if (pos == std::string::npos) return defaultValue;
    pos++;

    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    // Parse number
    std::string numStr;
    while (pos < json.size() && (isdigit(json[pos]) || json[pos] == '-')) {
        numStr += json[pos++];
    }

    if (numStr.empty()) return defaultValue;
    return std::stoi(numStr);
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

    // Wait/Synchronization endpoints
    HttpServer::RegisterEndpoint("/api/wait/paused", WaitForPaused);
    HttpServer::RegisterEndpoint("/api/wait/running", WaitForRunning);
    HttpServer::RegisterEndpoint("/api/wait/debugging", WaitForDebugging);

    LogInfo("Registered %d API endpoints", 19);
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

// =============================================================================
// Wait/Synchronization Functions
// =============================================================================

std::string WaitForPaused(const std::string& jsonBody) {
    // Parse timeout from JSON body (default: 30 seconds)
    int timeoutMs = ParseJsonInt(jsonBody, "timeout", 30000);

    // Cap timeout to reasonable limits (100ms to 5 minutes)
    if (timeoutMs < 100) timeoutMs = 100;
    if (timeoutMs > 300000) timeoutMs = 300000;

    LogDebug("WaitForPaused: timeout=%dms", timeoutMs);

    auto startTime = std::chrono::steady_clock::now();
    int pollIntervalMs = 50;  // Poll every 50ms

    while (true) {
        // Check current state
        auto state = DebuggerState::Get();

        // Success: debugger is paused (debugging but not running)
        if (state.binaryLoaded && !state.isRunning) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime
            ).count();

            LogDebug("WaitForPaused: success after %lldms", elapsed);

            return Object({
                {"success", Bool(true)},
                {"state", String("paused")},
                {"elapsed_ms", std::to_string(elapsed)},
                {"current_address", String(state.currentAddress)}
            });
        }

        // Check timeout
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime
        ).count();

        if (elapsed >= timeoutMs) {
            LogDebug("WaitForPaused: timeout after %lldms (state=%s)", elapsed, state.state.c_str());

            return Object({
                {"success", Bool(false)},
                {"error", String("Timeout waiting for debugger to pause")},
                {"timeout_ms", std::to_string(timeoutMs)},
                {"elapsed_ms", std::to_string(elapsed)},
                {"current_state", String(state.state)}
            });
        }

        // Sleep before next poll
        std::this_thread::sleep_for(std::chrono::milliseconds(pollIntervalMs));
    }
}

std::string WaitForRunning(const std::string& jsonBody) {
    // Parse timeout from JSON body (default: 10 seconds)
    int timeoutMs = ParseJsonInt(jsonBody, "timeout", 10000);

    // Cap timeout to reasonable limits
    if (timeoutMs < 100) timeoutMs = 100;
    if (timeoutMs > 300000) timeoutMs = 300000;

    LogDebug("WaitForRunning: timeout=%dms", timeoutMs);

    auto startTime = std::chrono::steady_clock::now();
    int pollIntervalMs = 50;

    while (true) {
        auto state = DebuggerState::Get();

        // Success: debugger is running
        if (state.isRunning) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime
            ).count();

            LogDebug("WaitForRunning: success after %lldms", elapsed);

            return Object({
                {"success", Bool(true)},
                {"state", String("running")},
                {"elapsed_ms", std::to_string(elapsed)}
            });
        }

        // Check timeout
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime
        ).count();

        if (elapsed >= timeoutMs) {
            LogDebug("WaitForRunning: timeout after %lldms (state=%s)", elapsed, state.state.c_str());

            return Object({
                {"success", Bool(false)},
                {"error", String("Timeout waiting for debugger to run")},
                {"timeout_ms", std::to_string(timeoutMs)},
                {"elapsed_ms", std::to_string(elapsed)},
                {"current_state", String(state.state)}
            });
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(pollIntervalMs));
    }
}

std::string WaitForDebugging(const std::string& jsonBody) {
    // Parse timeout from JSON body (default: 30 seconds)
    int timeoutMs = ParseJsonInt(jsonBody, "timeout", 30000);

    // Cap timeout to reasonable limits
    if (timeoutMs < 100) timeoutMs = 100;
    if (timeoutMs > 300000) timeoutMs = 300000;

    LogDebug("WaitForDebugging: timeout=%dms", timeoutMs);

    auto startTime = std::chrono::steady_clock::now();
    int pollIntervalMs = 50;

    while (true) {
        auto state = DebuggerState::Get();

        // Success: binary is loaded (debugging started)
        if (state.binaryLoaded) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime
            ).count();

            LogDebug("WaitForDebugging: success after %lldms", elapsed);

            return Object({
                {"success", Bool(true)},
                {"state", String(state.state)},
                {"elapsed_ms", std::to_string(elapsed)},
                {"is_running", Bool(state.isRunning)}
            });
        }

        // Check timeout
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime
        ).count();

        if (elapsed >= timeoutMs) {
            LogDebug("WaitForDebugging: timeout after %lldms", elapsed);

            return Object({
                {"success", Bool(false)},
                {"error", String("Timeout waiting for debugging to start")},
                {"timeout_ms", std::to_string(timeoutMs)},
                {"elapsed_ms", std::to_string(elapsed)},
                {"current_state", String(state.state)}
            });
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(pollIntervalMs));
    }
}

}  // namespace Commands
