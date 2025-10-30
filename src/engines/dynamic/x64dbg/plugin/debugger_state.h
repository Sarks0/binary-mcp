#pragma once

#include <string>

// Tracks debugger state
struct DebuggerState {
    std::string state;           // "not_loaded", "loaded", "running", "paused"
    bool binaryLoaded;
    std::string binaryPath;
    bool isRunning;
    std::string currentAddress;

    static DebuggerState Get();
};
