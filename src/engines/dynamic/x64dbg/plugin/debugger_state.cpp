#include "debugger_state.h"
#include "plugin.h"
#include <cstdio>

// Helper function to safely call x64dbg API functions with SEH protection
// CRITICAL: This function uses only POD types (no C++ objects with destructors)
// so it's safe to use __try/__except (SEH requires no C++ unwinding)
static bool SafeCallDbgAPI(bool* outIsRunning, bool* outBinaryLoaded) {
    // Use SEH (__try/__except) not C++ try/catch
    // C++ exceptions don't catch access violations (0xC0000005)
    // We use /FORCE:UNRESOLVED so these functions might not be properly resolved
    __try {
        *outIsRunning = DbgIsRunning();
        *outBinaryLoaded = DbgIsDebugging();
        return true;  // Success
    }
    __except(GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
             EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        // Catch access violations from unresolved x64dbg API functions
        LogError("Access violation calling x64dbg API (exception 0x%08X)", GetExceptionCode());
        *outIsRunning = false;
        *outBinaryLoaded = false;
        return false;  // Failed
    }
}

DebuggerState DebuggerState::Get() {
    DebuggerState state;

    // Call x64dbg API functions via SEH-protected helper
    // (Can't use __try/__except here because DebuggerState has std::string members)
    bool apiSuccess = SafeCallDbgAPI(&state.isRunning, &state.binaryLoaded);

    if (!apiSuccess) {
        // API call failed (access violation)
        state.state = "error";
        state.isRunning = false;
        state.binaryLoaded = false;
        state.currentAddress = "0x0";
        state.binaryPath = "";
        return state;
    }

    // Populate state based on API results
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

    return state;
}
