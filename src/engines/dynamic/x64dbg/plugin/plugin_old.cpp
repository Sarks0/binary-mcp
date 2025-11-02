#include "plugin.h"
#include "http_server.h"
#include "commands.h"
#include <cstdio>
#include <cstdarg>

// Plugin globals
int g_pluginHandle = 0;
HWND g_hwndDlg = nullptr;
int g_hMenu = 0;
int g_hMenuDisasm = 0;
int g_hMenuDump = 0;
int g_hMenuStack = 0;

// Timer for delayed HTTP server initialization
static HANDLE g_initTimer = nullptr;
static bool g_serverStarted = false;

// Timer callback for delayed HTTP server initialization
// This runs AFTER plugin loading is complete, avoiding loader lock issues
static VOID CALLBACK DelayedInitCallback(PVOID lpParam, BOOLEAN TimerOrWaitFired) {
    if (g_serverStarted) {
        return;  // Already started
    }

    LogInfo("Starting HTTP server (delayed initialization)...");

    // Now it's safe to initialize HTTP server, create threads, etc.
    // We're no longer in DLL load context
    __try {
        if (!HttpServer::Initialize(8765)) {
            LogError("Failed to initialize HTTP server");
            return;
        }

        // Register custom commands
        Commands::RegisterAll();

        LogInfo("HTTP API available at: http://localhost:8765");
        g_serverStarted = true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LogError("Exception during delayed initialization: 0x%08X", GetExceptionCode());
    }

    // Clean up the timer
    if (g_initTimer) {
        DeleteTimerQueueTimer(nullptr, g_initTimer, nullptr);
        g_initTimer = nullptr;
    }
}

// Logging helpers
void LogInfo(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    _plugin_logprintf("[MCP] %s\n", buffer);
}

void LogError(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    _plugin_logprintf("[MCP ERROR] %s\n", buffer);
}

void LogDebug(const char* format, ...) {
#ifdef _DEBUG
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    _plugin_logprintf("[MCP DEBUG] %s\n", buffer);
#endif
}

// Plugin initialization
bool pluginInit(PLUG_INITSTRUCT* initStruct) {
    g_pluginHandle = initStruct->pluginHandle;

    LogInfo("Initializing MCP Bridge Plugin v%s", PLUGIN_VERSION_STR);
    LogInfo("Plugin initialized - waiting for setup phase");

    return true;
}

void pluginStop() {
    LogInfo("Stopping plugin");

    // Cancel pending timer if still active
    if (g_initTimer) {
        DeleteTimerQueueTimer(nullptr, g_initTimer, INVALID_HANDLE_VALUE);
        g_initTimer = nullptr;
    }

    // Shutdown HTTP server
    HttpServer::Shutdown();

    LogInfo("Plugin stopped");
}

void pluginSetup() {
    LogInfo("Setting up plugin");

    // CRITICAL: Don't start HTTP server immediately!
    // Creating threads and initializing network during plugin load causes crashes
    // Use timer to delay initialization until after plugin load completes (2 seconds)
    // This avoids Windows loader lock issues

    if (!CreateTimerQueueTimer(&g_initTimer, nullptr, DelayedInitCallback,
                                nullptr, 2000, 0, WT_EXECUTEONLYONCE)) {
        LogError("Failed to create initialization timer: %d", GetLastError());
        // Fallback: try immediate initialization (risky but better than nothing)
        DelayedInitCallback(nullptr, FALSE);
    } else {
        LogInfo("HTTP server will start in 2 seconds (delayed init)");
    }

    // Add menu items (safe to do immediately)
    if (g_hMenu) {
        _plugin_menuaddentry(g_hMenu, 0, "&About");
        _plugin_menuaddentry(g_hMenu, 1, "&Status");
    }
}

// Plugin exports (required by x64dbg)
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct) {
    return pluginInit(initStruct);
}

extern "C" __declspec(dllexport) bool plugstop() {
    pluginStop();
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    g_hMenu = setupStruct->hMenu;
    g_hMenuDisasm = setupStruct->hMenuDisasm;
    g_hMenuDump = setupStruct->hMenuDump;
    g_hMenuStack = setupStruct->hMenuStack;
    pluginSetup();
}

// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
