// Temporary stub implementations of x64dbg API functions
// These allow the plugin to link when built standalone
// When loaded by x64dbg, the real implementations are provided by the host

#include "plugin.h"
#include <cstdarg>
#include <cstdio>

// Stub implementations - will be replaced by x64dbg at runtime
extern "C" {

// Logging function stub
__declspec(dllexport) void _plugin_logprintf(const char* format, ...) {
    // In standalone build, just print to stdout
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

// Menu function stub
__declspec(dllexport) void _plugin_menuaddentry(int hMenu, int hEntry, const char* title) {
    // No-op in standalone build
    (void)hMenu;
    (void)hEntry;
    (void)title;
}

// Debug API stubs
__declspec(dllexport) bool DbgIsDebugging() {
    // Return false in standalone build
    return false;
}

__declspec(dllexport) bool DbgIsRunning() {
    // Return false in standalone build
    return false;
}

}  // extern "C"
