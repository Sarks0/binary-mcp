#include "plugin.h"
#include "../pipe_protocol.h"
#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>

// Plugin globals
int g_pluginHandle = 0;
HWND g_hwndDlg = nullptr;
int g_hMenu = 0;
int g_hMenuDisasm = 0;
int g_hMenuDump = 0;
int g_hMenuStack = 0;

// DLL module handle (saved from DllMain)
static HMODULE g_hModule = nullptr;

// Server process handle
static HANDLE g_serverProcess = nullptr;
static HANDLE g_pipeServer = INVALID_HANDLE_VALUE;
static HANDLE g_pipeThread = nullptr;
static HANDLE g_shutdownEvent = nullptr;  // Event to signal shutdown
static bool g_running = false;

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

// Named Pipe server thread (handles requests from HTTP server process)
static DWORD WINAPI PipeServerThread(LPVOID lpParam) {
    LogInfo("Named Pipe server thread starting...");

    while (g_running) {
        // Create named pipe instance with FILE_FLAG_OVERLAPPED for async operations
        g_pipeServer = CreateNamedPipeA(
            Protocol::PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,  // Max instances
            Protocol::MAX_MESSAGE_SIZE,
            Protocol::MAX_MESSAGE_SIZE,
            0,
            nullptr
        );

        if (g_pipeServer == INVALID_HANDLE_VALUE) {
            LogError("Failed to create named pipe: %d", GetLastError());
            return 1;
        }

        LogInfo("Waiting for HTTP server to connect...");

        // Use overlapped I/O for interruptible ConnectNamedPipe
        OVERLAPPED overlapped = {};
        overlapped.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);

        BOOL connected = ConnectNamedPipe(g_pipeServer, &overlapped);
        DWORD error = GetLastError();

        if (!connected && error == ERROR_IO_PENDING) {
            // Wait for connection or shutdown event
            HANDLE waitHandles[2] = { overlapped.hEvent, g_shutdownEvent };
            DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

            if (waitResult == WAIT_OBJECT_0) {
                // Connection succeeded
                LogInfo("HTTP server connected to pipe");
            } else {
                // Shutdown event signaled
                CancelIo(g_pipeServer);
                CloseHandle(overlapped.hEvent);
                CloseHandle(g_pipeServer);
                g_pipeServer = INVALID_HANDLE_VALUE;
                LogInfo("Pipe server thread shutting down (no connection)");
                return 0;
            }
        } else if (!connected && error != ERROR_PIPE_CONNECTED) {
            LogError("ConnectNamedPipe failed: %d", error);
            CloseHandle(overlapped.hEvent);
            CloseHandle(g_pipeServer);
            g_pipeServer = INVALID_HANDLE_VALUE;
            continue;
        } else {
            LogInfo("HTTP server connected to pipe");
        }

        CloseHandle(overlapped.hEvent);

        // Handle requests from HTTP server
        while (g_running) {
            // Read request length
            uint32_t requestLength = 0;
            DWORD bytesRead = 0;

            if (!ReadFile(g_pipeServer, &requestLength, sizeof(requestLength), &bytesRead, nullptr)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) {
                    LogInfo("HTTP server disconnected");
                } else {
                    LogError("Failed to read request length: %d", GetLastError());
                }
                break;
            }

            if (requestLength > Protocol::MAX_MESSAGE_SIZE) {
                LogError("Request too large: %u bytes", requestLength);
                break;
            }

            // Read request data
            std::vector<char> buffer(requestLength);
            if (!ReadFile(g_pipeServer, buffer.data(), requestLength, &bytesRead, nullptr)) {
                LogError("Failed to read request: %d", GetLastError());
                break;
            }

            std::string request(buffer.data(), requestLength);
            LogInfo("Received request: %s", request.c_str());

            // TODO: Parse request and execute x64dbg API calls
            // For now, just send a simple response
            std::string response = "{\"status\":0,\"data\":{\"message\":\"OK\"}}";

            // Send response
            uint32_t responseLength = static_cast<uint32_t>(response.size());
            DWORD bytesWritten = 0;

            if (!WriteFile(g_pipeServer, &responseLength, sizeof(responseLength), &bytesWritten, nullptr)) {
                LogError("Failed to write response length: %d", GetLastError());
                break;
            }

            if (!WriteFile(g_pipeServer, response.c_str(), responseLength, &bytesWritten, nullptr)) {
                LogError("Failed to write response: %d", GetLastError());
                break;
            }
        }

        // Disconnect client
        DisconnectNamedPipe(g_pipeServer);
        CloseHandle(g_pipeServer);
        g_pipeServer = INVALID_HANDLE_VALUE;
    }

    LogInfo("Named Pipe server thread stopped");
    return 0;
}

// Spawn HTTP server process
static bool SpawnHTTPServer() {
    // Get plugin directory
    char pluginPath[MAX_PATH];
    if (!GetModuleFileNameA(g_hModule, pluginPath, MAX_PATH)) {
        LogError("Failed to get plugin path: %d", GetLastError());
        return false;
    }

    // Get directory containing plugin
    char* lastSlash = strrchr(pluginPath, '\\');
    if (lastSlash) {
        *(lastSlash + 1) = '\0';
    }

    // Build path to server executable
    char serverPath[MAX_PATH];
    snprintf(serverPath, MAX_PATH, "%sx64dbg_mcp_server.exe", pluginPath);

    LogInfo("Spawning HTTP server: %s", serverPath);

    // Spawn process
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(
        serverPath,
        nullptr,  // Command line
        nullptr,  // Process attributes
        nullptr,  // Thread attributes
        FALSE,    // Inherit handles
        0,        // Creation flags
        nullptr,  // Environment
        nullptr,  // Current directory
        &si,
        &pi
    )) {
        LogError("Failed to spawn HTTP server: %d", GetLastError());
        LogError("Make sure x64dbg_mcp_server.exe is in the same directory as the plugin");
        return false;
    }

    g_serverProcess = pi.hProcess;
    CloseHandle(pi.hThread);  // Don't need thread handle

    LogInfo("HTTP server process started (PID: %d)", pi.dwProcessId);
    return true;
}

// Menu callback handler (handles all menu entries)
void MenuEntryCallback(CBTYPE cbType, PLUG_CB_MENUENTRY* info) {
    switch (info->hEntry) {
        case 0: {  // About
            MessageBoxA(
                nullptr,
                "x64dbg MCP Bridge Plugin\n\n"
                "Version: 1.0\n"
                "Architecture: External Process\n\n"
                "This plugin provides MCP (Model Context Protocol) integration\n"
                "for x64dbg, allowing AI assistants to interact with the debugger.\n\n"
                "Components:\n"
                "- Named Pipe server in plugin DLL\n"
                "- HTTP REST API server (external process)\n"
                "- Crash-isolated architecture\n\n"
                "Status: Server running on http://127.0.0.1:8765\n"
                "Pipe: \\\\.\\pipe\\x64dbg_mcp",
                "About x64dbg_mcp",
                MB_OK | MB_ICONINFORMATION
            );
            break;
        }

        case 1: {  // Status
            char statusMsg[512];

            const char* pipeStatus = (g_pipeServer != INVALID_HANDLE_VALUE) ? "Connected" : "Disconnected";
            const char* serverStatus = (g_serverProcess != nullptr) ? "Running" : "Not Running";
            DWORD serverPid = 0;
            if (g_serverProcess) {
                serverPid = GetProcessId(g_serverProcess);
            }

            snprintf(statusMsg, sizeof(statusMsg),
                "MCP Bridge Plugin Status\n\n"
                "Plugin State: %s\n"
                "Named Pipe: %s\n"
                "HTTP Server: %s\n"
                "Server PID: %lu\n"
                "Server Port: 8765\n\n"
                "Pipe Name: \\\\.\\pipe\\x64dbg_mcp\n"
                "HTTP Endpoint: http://127.0.0.1:8765",
                g_running ? "Running" : "Stopped",
                pipeStatus,
                serverStatus,
                serverPid
            );

            MessageBoxA(nullptr, statusMsg, "x64dbg_mcp Status", MB_OK | MB_ICONINFORMATION);
            break;
        }
    }
}

// Plugin initialization
bool pluginInit(PLUG_INITSTRUCT* initStruct) {
    g_pluginHandle = initStruct->pluginHandle;
    LogInfo("Initializing MCP Bridge Plugin v%d", PLUGIN_VERSION);
    return true;
}

void pluginStop() {
    LogInfo("Stopping plugin");

    // Stop pipe server
    g_running = false;

    // Signal shutdown event to wake up pipe thread
    if (g_shutdownEvent) {
        SetEvent(g_shutdownEvent);
    }

    // Close pipe to force any pending I/O to complete
    if (g_pipeServer != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(g_pipeServer);
        CloseHandle(g_pipeServer);
        g_pipeServer = INVALID_HANDLE_VALUE;
    }

    // Wait for pipe thread to exit (should be quick now with shutdown event)
    if (g_pipeThread) {
        DWORD waitResult = WaitForSingleObject(g_pipeThread, 1000);
        if (waitResult == WAIT_TIMEOUT) {
            LogError("Pipe thread did not exit in time");
        }
        CloseHandle(g_pipeThread);
        g_pipeThread = nullptr;
    }

    // Cleanup shutdown event
    if (g_shutdownEvent) {
        CloseHandle(g_shutdownEvent);
        g_shutdownEvent = nullptr;
    }

    // Gracefully terminate server process (send Ctrl+C first)
    if (g_serverProcess) {
        LogInfo("Terminating HTTP server process...");

        // Try graceful shutdown first
        if (!GenerateConsoleCtrlEvent(CTRL_C_EVENT, GetProcessId(g_serverProcess))) {
            // If that fails, terminate forcefully
            TerminateProcess(g_serverProcess, 0);
        }

        WaitForSingleObject(g_serverProcess, 2000);
        CloseHandle(g_serverProcess);
        g_serverProcess = nullptr;
    }

    LogInfo("Plugin stopped");
}

void pluginSetup() {
    LogInfo("Setting up plugin");

    // Create shutdown event for graceful termination
    g_shutdownEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!g_shutdownEvent) {
        LogError("Failed to create shutdown event: %d", GetLastError());
        return;
    }

    // Start Named Pipe server thread (safe to do here - no loader lock issues)
    g_running = true;
    DWORD threadId;
    g_pipeThread = CreateThread(
        nullptr,
        0,
        PipeServerThread,
        nullptr,
        0,
        &threadId
    );

    if (!g_pipeThread) {
        LogError("Failed to create pipe server thread: %d", GetLastError());
        CloseHandle(g_shutdownEvent);
        g_shutdownEvent = nullptr;
        return;
    }

    // Give pipe thread time to create the pipe
    Sleep(100);

    // Spawn HTTP server process
    if (!SpawnHTTPServer()) {
        LogError("Failed to spawn HTTP server");
        return;
    }

    // Register menu callback
    _plugin_registercallback(g_pluginHandle, CB_MENUENTRY, (CBPLUGIN)MenuEntryCallback);

    // Add menu items
    if (g_hMenu) {
        _plugin_menuaddentry(g_hMenu, 0, "&About");
        _plugin_menuaddentry(g_hMenu, 1, "&Status");
    }

    LogInfo("Plugin setup complete - HTTP server should connect soon");
}

// Plugin exports (required by x64dbg)
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct) {
    // Initialize SDK version info (CRITICAL - x64dbg needs this!)
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    g_pluginHandle = initStruct->pluginHandle;

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
        g_hModule = hinstDLL;  // Save module handle for later use
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
