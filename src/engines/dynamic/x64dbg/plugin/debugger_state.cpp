#include "debugger_state.h"
#include "plugin.h"
#include <cstdio>

DebuggerState DebuggerState::Get() {
    DebuggerState state;

    // Use core x64dbg plugin API functions (available from _plugins.h)
    // CRITICAL: Use SEH (__try/__except) not C++ try/catch
    // C++ exceptions don't catch access violations (0xC0000005)
    // We use /FORCE:UNRESOLVED so these functions might not be properly resolved
    __try {
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
    __except(GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
             EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        // Catch access violations from unresolved x64dbg API functions
        LogError("Access violation calling x64dbg API (exception 0x%08X)", GetExceptionCode());
        state.state = "error";
        state.isRunning = false;
        state.binaryLoaded = false;
        state.currentAddress = "0x0";
        state.binaryPath = "";
    }

    return state;
}
