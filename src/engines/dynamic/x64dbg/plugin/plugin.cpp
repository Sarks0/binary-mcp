#include "pluginsdk/_plugins.h"
#include "pluginsdk/_scriptapi.h"
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

    // Initialize HTTP server
    if (!HttpServer::Initialize(8765)) {
        LogError("Failed to initialize HTTP server");
        return false;
    }

    // Register custom commands
    Commands::RegisterAll();

    LogInfo("Plugin initialized successfully");
    LogInfo("HTTP API available at: http://localhost:8765");

    return true;
}

void pluginStop() {
    LogInfo("Stopping plugin");

    // Shutdown HTTP server
    HttpServer::Shutdown();

    LogInfo("Plugin stopped");
}

void pluginSetup() {
    LogInfo("Setting up plugin UI");

    // Add menu items if needed
    _plugin_menuaddentry(g_hMenu, 0, "&About");
    _plugin_menuaddentry(g_hMenu, 1, "&Status");
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
