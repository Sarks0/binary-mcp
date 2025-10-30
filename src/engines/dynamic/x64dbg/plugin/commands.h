#pragma once

#include <string>

// Debugger commands exposed via HTTP API
namespace Commands {
    void RegisterAll();

    // Debugger control
    std::string Status(const std::string& jsonBody);
    std::string LoadBinary(const std::string& jsonBody);
    std::string Run(const std::string& jsonBody);
    std::string Pause(const std::string& jsonBody);
    std::string StepInto(const std::string& jsonBody);
    std::string StepOver(const std::string& jsonBody);
    std::string StepOut(const std::string& jsonBody);

    // Breakpoints
    std::string SetBreakpoint(const std::string& jsonBody);
    std::string DeleteBreakpoint(const std::string& jsonBody);
    std::string ListBreakpoints(const std::string& jsonBody);

    // Information
    std::string GetRegisters(const std::string& jsonBody);
    std::string GetStack(const std::string& jsonBody);
    std::string GetModules(const std::string& jsonBody);
    std::string GetThreads(const std::string& jsonBody);

    // Memory
    std::string ReadMemory(const std::string& jsonBody);
    std::string WriteMemory(const std::string& jsonBody);
    std::string Disassemble(const std::string& jsonBody);
}
