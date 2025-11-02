#include "debugger_state.h"
#include "plugin.h"
#include <cstdio>

DebuggerState DebuggerState::Get() {
    DebuggerState state;

    // Use core x64dbg plugin API functions (available from _plugins.h)
    // These are safe to call after plugin initialization
    try {
        state.isRunning = DbgIsRunning();
        state.binaryLoaded = DbgIsDebugging();

        if (state.isRunning) {
            state.state = "running";
        } else if (state.binaryLoaded) {
            state.state = "paused";
        } else {
            state.state = "not_loaded";
        }

        // TODO: Get current address using proper x64dbg API
        // Register::Get(Register::RIP) requires Script API headers we don't have
        if (state.binaryLoaded) {
            state.currentAddress = "0x0";  // Stub for now
            state.binaryPath = "";  // Stub for now
        }
    }
    catch (...) {
        // Fallback if x64dbg API calls fail
        LogError("Failed to get debugger state");
        state.state = "error";
        state.isRunning = false;
        state.binaryLoaded = false;
        state.currentAddress = "0x0";
        state.binaryPath = "";
    }

    return state;
}
