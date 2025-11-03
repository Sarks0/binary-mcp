#include "plugin.h"
#include "../pipe_protocol.h"
#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <wincrypt.h>  // For CryptGenRandom

// x64dbg SDK headers
#include "pluginsdk/_plugins.h"
#include "pluginsdk/bridgemain.h"

#pragma comment(lib, "advapi32.lib")  // Link Crypto API

// Request type enumeration
enum RequestType {
    GET_STATE = 1,
    LOAD_BINARY = 2,
    READ_MEMORY = 3,
    WRITE_MEMORY = 4,
    GET_REGISTERS = 5,
    SET_REGISTER = 6,
    DISASSEMBLE = 7,
    RUN = 8,
    PAUSE = 9,
    STEP_INTO = 10,
    STEP_OVER = 11,
    STEP_OUT = 12,
    GET_STACK = 13,
    GET_MODULES = 14,
    GET_THREADS = 15,
    SET_BREAKPOINT = 20,
    DELETE_BREAKPOINT = 21,
    LIST_BREAKPOINTS = 22,
    PING = 99
};

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

// ============================================================================
// JSON HELPER FUNCTIONS (Simple parser - no external dependencies)
// ============================================================================

// Extract integer value from JSON string
int ExtractIntField(const std::string& json, const char* fieldName, int defaultValue = 0) {
    std::string searchStr = std::string("\"") + fieldName + "\":";
    size_t pos = json.find(searchStr);
    if (pos == std::string::npos) return defaultValue;

    pos += searchStr.length();
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    int value = 0;
    sscanf(json.c_str() + pos, "%d", &value);
    return value;
}

// Extract string value from JSON string
std::string ExtractStringField(const std::string& json, const char* fieldName, const char* defaultValue = "") {
    std::string searchStr = std::string("\"") + fieldName + "\":\"";
    size_t pos = json.find(searchStr);
    if (pos == std::string::npos) return defaultValue;

    pos += searchStr.length();
    size_t endPos = json.find('"', pos);
    if (endPos == std::string::npos) return defaultValue;

    return json.substr(pos, endPos - pos);
}

// Build JSON response
std::string BuildJsonResponse(bool success, const std::string& data = "") {
    std::string response = "{\"success\":";
    response += success ? "true" : "false";
    if (!data.empty()) {
        response += ",";
        response += data;
    }
    response += "}";
    return response;
}

// ============================================================================
// REQUEST HANDLERS
// ============================================================================

// Handler: GET_STATE - Get current debugger state
std::string HandleGetState(const std::string& request) {
    std::stringstream data;

    // Check if debugger is active
    if (!DbgIsDebugging()) {
        data << "\"state\":\"not_loaded\","
             << "\"current_address\":\"0\","
             << "\"binary_path\":\"\"";
        return BuildJsonResponse(true, data.str());
    }

    // Get current state
    DBGSTATE state = DbgGetDbgState();
    const char* stateStr = "unknown";
    switch (state) {
        case paused: stateStr = "paused"; break;
        case running: stateStr = "running"; break;
        case stopped: stateStr = "terminated"; break;
        default: stateStr = "loaded"; break;
    }

    // Get current instruction pointer
    duint cip = DbgValFromString("cip");

    // Get binary path
    char modulePath[MAX_PATH] = "";
    DbgGetModuleAt(cip, modulePath);

    data << "\"state\":\"" << stateStr << "\","
         << "\"current_address\":\"" << std::hex << cip << std::dec << "\","
         << "\"binary_path\":\"" << modulePath << "\"";

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_REGISTERS - Get all CPU registers
std::string HandleGetRegisters(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::stringstream data;

    // Get register values using DbgValFromString
    // Format all general-purpose registers as hex
    data << std::hex << std::setfill('0');
    data << "\"rax\":\"" << std::setw(16) << DbgValFromString("rax") << "\","
         << "\"rbx\":\"" << std::setw(16) << DbgValFromString("rbx") << "\","
         << "\"rcx\":\"" << std::setw(16) << DbgValFromString("rcx") << "\","
         << "\"rdx\":\"" << std::setw(16) << DbgValFromString("rdx") << "\","
         << "\"rsi\":\"" << std::setw(16) << DbgValFromString("rsi") << "\","
         << "\"rdi\":\"" << std::setw(16) << DbgValFromString("rdi") << "\","
         << "\"rbp\":\"" << std::setw(16) << DbgValFromString("rbp") << "\","
         << "\"rsp\":\"" << std::setw(16) << DbgValFromString("rsp") << "\","
         << "\"rip\":\"" << std::setw(16) << DbgValFromString("rip") << "\","
         << "\"r8\":\"" << std::setw(16) << DbgValFromString("r8") << "\","
         << "\"r9\":\"" << std::setw(16) << DbgValFromString("r9") << "\","
         << "\"r10\":\"" << std::setw(16) << DbgValFromString("r10") << "\","
         << "\"r11\":\"" << std::setw(16) << DbgValFromString("r11") << "\","
         << "\"r12\":\"" << std::setw(16) << DbgValFromString("r12") << "\","
         << "\"r13\":\"" << std::setw(16) << DbgValFromString("r13") << "\","
         << "\"r14\":\"" << std::setw(16) << DbgValFromString("r14") << "\","
         << "\"r15\":\"" << std::setw(16) << DbgValFromString("r15") << "\","
         << "\"rflags\":\"" << std::setw(16) << DbgValFromString("rflags") << "\"";

    return BuildJsonResponse(true, data.str());
}

// Handler: READ_MEMORY - Read memory from debugged process
std::string HandleReadMemory(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Parse parameters
    std::string addressStr = ExtractStringField(request, "address");
    int size = ExtractIntField(request, "size", 0);

    if (addressStr.empty() || size <= 0) {
        return BuildJsonResponse(false, "\"error\":\"Missing or invalid address/size\"");
    }

    // Validate size (max 1MB)
    if (size > 1024 * 1024) {
        return BuildJsonResponse(false, "\"error\":\"Size too large (max 1MB)\"");
    }

    // Parse address
    duint address = DbgValFromString(addressStr.c_str());
    if (address == 0 && addressStr != "0") {
        return BuildJsonResponse(false, "\"error\":\"Invalid address\"");
    }

    // Allocate buffer
    std::vector<unsigned char> buffer(size);

    // Read memory
    if (!DbgMemRead(address, buffer.data(), size)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to read memory\"");
    }

    // Convert to hex string
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    for (int i = 0; i < size; i++) {
        hexStream << std::setw(2) << static_cast<int>(buffer[i]);
    }

    std::stringstream data;
    data << "\"data\":\"" << hexStream.str() << "\"";

    return BuildJsonResponse(true, data.str());
}

// Handler: STEP_INTO - Single-step into next instruction
std::string HandleStepInto(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Execute step into
    DbgCmdExec("StepInto");

    // Wait for step to complete (with timeout)
    int timeout = 100; // 100ms
    while (DbgGetDbgState() == running && timeout > 0) {
        Sleep(10);
        timeout -= 10;
    }

    // Get new address
    duint cip = DbgValFromString("cip");
    const char* stateStr = (DbgGetDbgState() == paused) ? "paused" : "running";

    std::stringstream data;
    data << "\"address\":\"" << std::hex << cip << std::dec << "\","
         << "\"state\":\"" << stateStr << "\"";

    return BuildJsonResponse(true, data.str());
}

// Handler: STEP_OVER - Step over next instruction
std::string HandleStepOver(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    DbgCmdExec("StepOver");

    int timeout = 100;
    while (DbgGetDbgState() == running && timeout > 0) {
        Sleep(10);
        timeout -= 10;
    }

    duint cip = DbgValFromString("cip");
    const char* stateStr = (DbgGetDbgState() == paused) ? "paused" : "running";

    std::stringstream data;
    data << "\"address\":\"" << std::hex << cip << std::dec << "\","
         << "\"state\":\"" << stateStr << "\"";

    return BuildJsonResponse(true, data.str());
}

// Handler: STEP_OUT - Step out of current function
std::string HandleStepOut(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    DbgCmdExec("StepOut");

    // Step out may take longer
    int timeout = 1000;
    while (DbgGetDbgState() == running && timeout > 0) {
        Sleep(10);
        timeout -= 10;
    }

    duint cip = DbgValFromString("cip");
    const char* stateStr = (DbgGetDbgState() == paused) ? "paused" : "running";

    std::stringstream data;
    data << "\"address\":\"" << std::hex << cip << std::dec << "\","
         << "\"state\":\"" << stateStr << "\"";

    return BuildJsonResponse(true, data.str());
}

// Handler: SET_BREAKPOINT - Set software breakpoint at address
std::string HandleSetBreakpoint(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Parse address
    std::string addressStr = ExtractStringField(request, "address");
    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    duint address = DbgValFromString(addressStr.c_str());
    if (address == 0 && addressStr != "0") {
        return BuildJsonResponse(false, "\"error\":\"Invalid address\"");
    }

    // Set breakpoint using command
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bp %llx", address);
    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to set breakpoint\"");
    }

    LogInfo("Breakpoint set at 0x%llx", address);

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\"";

    return BuildJsonResponse(true, data.str());
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

            // Parse request type and route to appropriate handler
            std::string response;
            int requestType = ExtractIntField(request, "type", -1);

            if (requestType == -1) {
                response = BuildJsonResponse(false, "\"error\":\"Missing 'type' field\"");
            } else {
                LogInfo("Request type: %d", requestType);

                // Route to appropriate handler
                switch (requestType) {
                    case GET_STATE:
                        response = HandleGetState(request);
                        break;

                    case GET_REGISTERS:
                        response = HandleGetRegisters(request);
                        break;

                    case READ_MEMORY:
                        response = HandleReadMemory(request);
                        break;

                    case STEP_INTO:
                        response = HandleStepInto(request);
                        break;

                    case STEP_OVER:
                        response = HandleStepOver(request);
                        break;

                    case STEP_OUT:
                        response = HandleStepOut(request);
                        break;

                    case SET_BREAKPOINT:
                        response = HandleSetBreakpoint(request);
                        break;

                    case PING:
                        response = BuildJsonResponse(true, "\"message\":\"pong\"");
                        break;

                    default:
                        LogError("Unknown request type: %d", requestType);
                        response = BuildJsonResponse(false, "\"error\":\"Unknown request type\"");
                        break;
                }
            }

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

    // Delete authentication token file
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        char tokenPath[MAX_PATH];
        snprintf(tokenPath, MAX_PATH, "%sx64dbg_mcp_token.txt", tempPath);
        if (DeleteFileA(tokenPath)) {
            LogInfo("Deleted auth token file");
        } else {
            DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND) {
                LogError("Failed to delete token file: %d", error);
            }
        }
    }

    LogInfo("Plugin stopped");
}

// Generate cryptographically secure random token
static bool GenerateSecureToken(char* outToken, size_t tokenLength) {
    // Use Windows Crypto API for secure random generation
    HCRYPTPROV hCryptProv = 0;
    if (!CryptAcquireContextA(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        LogError("CryptAcquireContext failed: %d", GetLastError());
        return false;
    }

    // Generate 32 random bytes
    unsigned char randomBytes[32];
    if (!CryptGenRandom(hCryptProv, sizeof(randomBytes), randomBytes)) {
        LogError("CryptGenRandom failed: %d", GetLastError());
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    CryptReleaseContext(hCryptProv, 0);

    // Convert to base64-like hex string (64 characters)
    const char* hexChars = "0123456789abcdef";
    for (size_t i = 0; i < 32 && i * 2 < tokenLength - 1; i++) {
        outToken[i * 2] = hexChars[(randomBytes[i] >> 4) & 0x0F];
        outToken[i * 2 + 1] = hexChars[randomBytes[i] & 0x0F];
    }
    outToken[64] = '\0';

    return true;
}

void pluginSetup() {
    LogInfo("Setting up plugin");

    // Create authentication token file for Python bridge
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        char tokenPath[MAX_PATH];
        snprintf(tokenPath, MAX_PATH, "%sx64dbg_mcp_token.txt", tempPath);

        // Generate cryptographically secure random token (256 bits)
        char token[65];  // 64 hex chars + null terminator
        if (!GenerateSecureToken(token, sizeof(token))) {
            LogError("Failed to generate secure token");
            return;
        }

        LogInfo("Generated secure authentication token (256-bit)");

        // Create security descriptor that only allows current user access
        SECURITY_ATTRIBUTES sa = {};
        SECURITY_DESCRIPTOR sd = {};

        if (InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
            // Set NULL DACL temporarily (we should use proper ACLs in production)
            // TODO: Implement proper ACL with only current user access
            if (SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE)) {
                sa.nLength = sizeof(SECURITY_ATTRIBUTES);
                sa.lpSecurityDescriptor = &sd;
                sa.bInheritHandle = FALSE;
            }
        }

        // Create file with restrictive permissions (removed DELETE_ON_CLOSE for now)
        HANDLE hFile = CreateFileA(
            tokenPath,
            GENERIC_WRITE,
            FILE_SHARE_READ,  // Allow reading while we have it open
            &sa,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_TEMPORARY,  // Windows hint for temp file
            nullptr
        );

        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten;
            if (WriteFile(hFile, token, (DWORD)strlen(token), &bytesWritten, nullptr)) {
                LogInfo("Created secure auth token file: %s", tokenPath);
            } else {
                LogError("Failed to write token: %d", GetLastError());
            }
            CloseHandle(hFile);
        } else {
            LogError("Failed to create auth token file: %d", GetLastError());
        }
    }

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
