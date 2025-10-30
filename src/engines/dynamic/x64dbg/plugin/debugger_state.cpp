#include "debugger_state.h"
#include "pluginsdk/_scriptapi.h"
#include <cstdio>

using namespace Script;

DebuggerState DebuggerState::Get() {
    DebuggerState state;

    // Check if debugger is active
    state.isRunning = DbgIsRunning();
    state.binaryLoaded = DbgIsDebugging();

    if (state.isRunning) {
        state.state = "running";
    } else if (state.binaryLoaded) {
        state.state = "paused";
    } else {
        state.state = "not_loaded";
    }

    // Get current address
    if (state.binaryLoaded) {
        duint rip = Register::Get(Register::RIP);
        char buffer[32];
        sprintf_s(buffer, "%llX", rip);
        state.currentAddress = buffer;

        // Get module path
        char modPath[MAX_PATH];
        if (Module::GetMainModulePath(modPath)) {
            state.binaryPath = modPath;
        }
    }

    return state;
}
