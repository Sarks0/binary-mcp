#include "commands.h"
#include "http_server.h"
#include "debugger_state.h"
#include "plugin.h"
#include "pluginsdk/_scriptapi.h"
#include <sstream>
#include <iomanip>

using namespace Script;
using namespace Json;

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
    // Parse binary_path from JSON
    // TODO: Add proper JSON parsing
    // For now, use Script::Misc::OpenFile

    try {
        // This would be called from Python with proper path
        LogInfo("Load binary requested");
        return Object({
            {"success", Bool(true)},
            {"message", String("Binary loading not yet implemented")}
        });
    }
    catch (const std::exception& e) {
        return Object({
            {"success", Bool(false)},
            {"error", String(e.what())}
        });
    }
}

std::string Run(const std::string& jsonBody) {
    try {
        Debug::Run();
        return Object({
            {"success", Bool(true)},
            {"state", String("running")}
        });
    }
    catch (const std::exception& e) {
        return Object({
            {"success", Bool(false)},
            {"error", String(e.what())}
        });
    }
}

std::string Pause(const std::string& jsonBody) {
    try {
        Debug::Pause();
        return Object({
            {"success", Bool(true)},
            {"state", String("paused")}
        });
    }
    catch (const std::exception& e) {
        return Object({
            {"success", Bool(false)},
            {"error", String(e.what())}
        });
    }
}

std::string StepInto(const std::string& jsonBody) {
    try {
        Debug::StepIn();
        Debug::Wait();

        duint rip = Register::Get(Register::RIP);
        char ripStr[32];
        sprintf_s(ripStr, "%llX", rip);

        return Object({
            {"success", Bool(true)},
            {"address", String(ripStr)},
            {"registers", String("use /api/registers for full state")}
        });
    }
    catch (const std::exception& e) {
        return Object({
            {"success", Bool(false)},
            {"error", String(e.what())}
        });
    }
}

std::string StepOver(const std::string& jsonBody) {
    try {
        Debug::StepOver();
        Debug::Wait();

        duint rip = Register::Get(Register::RIP);
        char ripStr[32];
        sprintf_s(ripStr, "%llX", rip);

        return Object({
            {"success", Bool(true)},
            {"address", String(ripStr)}
        });
    }
    catch (const std::exception& e) {
        return Object({
            {"success", Bool(false)},
            {"error", String(e.what())}
        });
    }
}

std::string StepOut(const std::string& jsonBody) {
    try {
        Debug::StepOut();
        Debug::Wait();

        duint rip = Register::Get(Register::RIP);
        char ripStr[32];
        sprintf_s(ripStr, "%llX", rip);

        return Object({
            {"success", Bool(true)},
            {"address", String(ripStr)}
        });
    }
    catch (const std::exception& e) {
        return Object({
            {"success", Bool(false)},
            {"error", String(e.what())}
        });
    }
}

std::string SetBreakpoint(const std::string& jsonBody) {
    // TODO: Parse address from JSON
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
    try {
        char buffer[32];

        #define REG_STR(reg) sprintf_s(buffer, "%llX", Register::Get(Register::reg)), String(buffer)

        return Object({
            {"success", Bool(true)},
            {"rax", REG_STR(RAX)},
            {"rbx", REG_STR(RBX)},
            {"rcx", REG_STR(RCX)},
            {"rdx", REG_STR(RDX)},
            {"rsi", REG_STR(RSI)},
            {"rdi", REG_STR(RDI)},
            {"rbp", REG_STR(RBP)},
            {"rsp", REG_STR(RSP)},
            {"rip", REG_STR(RIP)},
            {"r8", REG_STR(R8)},
            {"r9", REG_STR(R9)},
            {"r10", REG_STR(R10)},
            {"r11", REG_STR(R11)},
            {"r12", REG_STR(R12)},
            {"r13", REG_STR(R13)},
            {"r14", REG_STR(R14)},
            {"r15", REG_STR(R15)}
        });

        #undef REG_STR
    }
    catch (const std::exception& e) {
        return Object({
            {"success", Bool(false)},
            {"error", String(e.what())}
        });
    }
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
