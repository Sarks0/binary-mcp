#include "plugin.h"
#include "event_system.h"
#include "../pipe_protocol.h"
#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <set>
#include <map>
#include <algorithm>
#include <cctype>
#include <wincrypt.h>  // For CryptGenRandom

// x64dbg SDK headers
#include "pluginsdk/_plugins.h"
#include "pluginsdk/bridgemain.h"

#pragma comment(lib, "advapi32.lib")  // Link Crypto API

// Request type enumeration (must match server/main.cpp)
enum RequestType {
    // Core debugger state
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

    // Breakpoints
    SET_BREAKPOINT = 20,
    DELETE_BREAKPOINT = 21,
    LIST_BREAKPOINTS = 22,
    SET_HARDWARE_BREAKPOINT = 30,
    SET_MEMORY_BREAKPOINT = 31,
    DELETE_MEMORY_BREAKPOINT = 32,

    // Analysis tools
    GET_INSTRUCTION = 40,
    EVALUATE_EXPRESSION = 41,

    // Memory tools
    GET_MEMORY_MAP = 50,
    GET_MEMORY_INFO = 51,
    DUMP_MEMORY = 52,
    SEARCH_MEMORY = 53,

    // Module tools
    GET_MODULE_IMPORTS = 60,
    GET_MODULE_EXPORTS = 61,

    // Comments
    SET_COMMENT = 70,
    GET_COMMENT = 71,

    // Advanced control
    SKIP_INSTRUCTION = 80,
    RUN_UNTIL_RETURN = 81,
    HIDE_DEBUGGER = 90,

    // Wait/Synchronization (Phase 1)
    WAIT_PAUSED = 91,
    WAIT_RUNNING = 92,
    WAIT_DEBUGGING = 93,

    // Symbol resolution
    RESOLVE_SYMBOL = 95,

    // Health check
    PING = 99,

    // Events
    GET_EVENTS = 100,
    CLEAR_EVENTS = 101,
    GET_EVENT_STATUS = 102,

    // Memory allocation (Phase 3)
    VIRT_ALLOC = 110,
    VIRT_FREE = 111,
    VIRT_PROTECT = 112,
    MEM_SET = 113,
    CHECK_VALID_PTR = 114,

    // Enhanced breakpoints (Phase 3)
    TOGGLE_BREAKPOINT = 120,
    DELETE_HARDWARE_BREAKPOINT = 121,
    TOGGLE_HARDWARE_BREAKPOINT = 122,
    TOGGLE_MEMORY_BREAKPOINT = 123,
    LIST_ALL_BREAKPOINTS = 124,

    // Phase 4: Tracing & String Analysis
    START_TRACE = 130,
    STOP_TRACE = 131,
    GET_TRACE_DATA = 132,
    CLEAR_TRACE = 133,
    SET_API_BREAKPOINT = 134,
    GET_API_LOG = 135,
    CLEAR_API_LOG = 136,

    // Phase 4: String & Pattern Search
    FIND_STRINGS = 140,
    PATTERN_SCAN = 141,
    XOR_DECRYPT = 142,

    // Phase 4: References & Analysis
    FIND_REFERENCES = 145,
    GET_CALL_STACK_DETAILED = 146,
    GET_XREFS_TO = 147,
    GET_XREFS_FROM = 148,

    // Phase 5: Anti-Debug Bypass
    HIDE_DEBUG_PEB = 150,
    HIDE_DEBUG_FULL = 151,
    GET_ANTI_DEBUG_STATUS = 152,
    PATCH_DBG_CHECK = 153,

    // Phase 6: Code Coverage
    START_COVERAGE = 160,
    STOP_COVERAGE = 161,
    GET_COVERAGE_DATA = 162,
    CLEAR_COVERAGE = 163,
    GET_COVERAGE_STATS = 164,
    EXPORT_COVERAGE = 165
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

// ============================================================================
// PHASE 4: TRACING & API LOGGING DATA STRUCTURES
// ============================================================================

// Trace entry for instruction tracing
struct TraceEntry {
    uint64_t address;
    uint64_t timestamp;  // Milliseconds since trace start
    std::string instruction;
    std::string module;
    uint32_t threadId;
};

// API call log entry
struct ApiCallEntry {
    uint64_t id;
    uint64_t address;        // Address of the API function
    uint64_t returnAddress;  // Where the call came from
    uint64_t timestamp;
    std::string apiName;
    std::string moduleName;
    std::vector<uint64_t> args;  // Up to 4 arguments
    uint64_t returnValue;
    bool hasReturned;
    uint32_t threadId;
};

// Global trace state
static struct {
    bool enabled;
    bool traceInto;  // true = trace into calls, false = trace over
    uint64_t startTime;
    uint64_t maxEntries;
    std::vector<TraceEntry> entries;
    std::string logFile;
    FILE* logFileHandle;

    void Reset() {
        enabled = false;
        traceInto = true;
        startTime = 0;
        maxEntries = 100000;
        entries.clear();
        logFile.clear();
        if (logFileHandle) {
            fclose(logFileHandle);
            logFileHandle = nullptr;
        }
    }
} g_traceState = {false, true, 0, 100000, {}, "", nullptr};

// Global API logging state
static struct {
    bool enabled;
    uint64_t nextId;
    uint64_t startTime;
    std::vector<ApiCallEntry> entries;
    std::set<std::string> watchedApis;  // APIs to log (empty = all)
    uint64_t maxEntries;

    void Reset() {
        enabled = false;
        nextId = 1;
        startTime = 0;
        entries.clear();
        watchedApis.clear();
        maxEntries = 10000;
    }
} g_apiLogState = {false, 1, 0, {}, {}, 10000};

// Mutex for thread safety
static CRITICAL_SECTION g_traceLock;
static CRITICAL_SECTION g_apiLogLock;
static bool g_locksInitialized = false;

void InitTraceLocks() {
    if (!g_locksInitialized) {
        InitializeCriticalSection(&g_traceLock);
        InitializeCriticalSection(&g_apiLogLock);
        g_locksInitialized = true;
    }
}

// ============================================================================
// PHASE 5: ANTI-DEBUG BYPASS STATE
// ============================================================================

static struct {
    bool pebPatched;
    bool ntGlobalFlagPatched;
    bool heapFlagsPatched;
    bool timingHooked;
    uint64_t fakeTickCount;
    uint64_t fakeQpcBase;

    void Reset() {
        pebPatched = false;
        ntGlobalFlagPatched = false;
        heapFlagsPatched = false;
        timingHooked = false;
        fakeTickCount = 0;
        fakeQpcBase = 0;
    }
} g_antiDebugState = {false, false, false, false, 0, 0};

// ============================================================================
// PHASE 6: CODE COVERAGE DATA STRUCTURES
// ============================================================================

// Coverage entry for tracking executed addresses
struct CoverageEntry {
    uint64_t address;
    uint64_t hitCount;
    uint64_t firstHitTime;
    uint64_t lastHitTime;
    std::string module;
    std::string symbol;
};

// Global coverage state
static struct {
    bool enabled;
    uint64_t startTime;
    std::map<uint64_t, CoverageEntry> entries;  // address -> entry
    std::set<uint64_t> basicBlocks;  // Set of basic block start addresses
    uint64_t totalHits;
    std::string moduleName;  // Filter to specific module (empty = all)

    void Reset() {
        enabled = false;
        startTime = 0;
        entries.clear();
        basicBlocks.clear();
        totalHits = 0;
        moduleName.clear();
    }
} g_coverageState = {false, 0, {}, {}, 0, ""};

static CRITICAL_SECTION g_coverageLock;
static bool g_coverageLockInitialized = false;

void InitCoverageLock() {
    if (!g_coverageLockInitialized) {
        InitializeCriticalSection(&g_coverageLock);
        g_coverageLockInitialized = true;
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

// ============================================================================
// JSON HELPER FUNCTIONS (Simple parser - no external dependencies)
// ============================================================================

// Escape string for JSON output (handles backslashes, quotes, newlines, etc.)
std::string JsonEscape(const std::string& str) {
    std::string result;
    result.reserve(str.length() * 2);  // Preallocate for potential escaping

    for (char c : str) {
        switch (c) {
            case '\\': result += "\\\\"; break;
            case '"':  result += "\\\""; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            default:
                // Handle control characters
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    result += buf;
                } else {
                    result += c;
                }
                break;
        }
    }
    return result;
}

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
// Handles both quoted strings ("field":"value") and unquoted values ("field":123)
std::string ExtractStringField(const std::string& json, const char* fieldName, const char* defaultValue = "") {
    std::string searchStr = std::string("\"") + fieldName + "\":";
    size_t pos = json.find(searchStr);
    if (pos == std::string::npos) {
        // Log for debugging
        LogInfo("ExtractStringField: field '%s' not found in: %.100s...", fieldName, json.c_str());
        return defaultValue;
    }

    pos += searchStr.length();

    // Skip whitespace
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    if (pos >= json.length()) return defaultValue;

    // Check if value is quoted or not
    if (json[pos] == '"') {
        // Quoted string value
        pos++;  // Skip opening quote
        std::string result;
        while (pos < json.length() && json[pos] != '"') {
            // Handle escape sequences
            if (json[pos] == '\\' && pos + 1 < json.length()) {
                pos++;
                switch (json[pos]) {
                    case 'n': result += '\n'; break;
                    case 'r': result += '\r'; break;
                    case 't': result += '\t'; break;
                    case '\\': result += '\\'; break;
                    case '"': result += '"'; break;
                    default: result += json[pos]; break;
                }
            } else {
                result += json[pos];
            }
            pos++;
        }
        return result;
    } else {
        // Unquoted value (number, boolean, null)
        // Read until comma, closing brace, or end
        size_t endPos = pos;
        while (endPos < json.length() &&
               json[endPos] != ',' &&
               json[endPos] != '}' &&
               json[endPos] != ']' &&
               json[endPos] != ' ' &&
               json[endPos] != '\t' &&
               json[endPos] != '\n' &&
               json[endPos] != '\r') {
            endPos++;
        }
        return json.substr(pos, endPos - pos);
    }
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

// Helper: Normalize symbol format to x64dbg's module!symbol format
// Converts common formats like module.function or module::function
std::string NormalizeSymbolFormat(const std::string& input) {
    if (input.empty()) return input;

    std::string result = input;

    // Check if it looks like a symbol (contains letters, not just hex)
    bool hasNonHex = false;
    for (char c : input) {
        if (!isxdigit(c) && c != 'x' && c != 'X') {
            hasNonHex = true;
            break;
        }
    }

    if (!hasNonHex) {
        // Pure hex address, return as-is
        return result;
    }

    // Already in correct format with exclamation mark
    if (result.find('!') != std::string::npos) {
        return result;
    }

    // Convert C++ namespace style (module::function) to module!function
    size_t doubleColon = result.find("::");
    if (doubleColon != std::string::npos) {
        result.replace(doubleColon, 2, "!");
        return result;
    }

    // Convert dot notation (module.function) to module!function
    // But be careful: some symbols legitimately contain dots
    // Only convert if it looks like module.function pattern
    size_t dot = result.find('.');
    if (dot != std::string::npos && dot > 0 && dot < result.length() - 1) {
        // Check if what's before the dot looks like a module name
        // (no spaces, not starting with a number)
        std::string beforeDot = result.substr(0, dot);
        if (!beforeDot.empty() && !isdigit(beforeDot[0]) &&
            beforeDot.find(' ') == std::string::npos) {
            result.replace(dot, 1, "!");
            return result;
        }
    }

    return result;
}

// Helper: Resolve address string to duint with detailed error reporting
// Returns 0 on failure and sets errorMsg
duint ResolveAddress(const std::string& addressStr, std::string& errorMsg) {
    if (addressStr.empty()) {
        errorMsg = "Missing address";
        return 0;
    }

    // Normalize symbol format (convert module.func or module::func to module!func)
    std::string normalizedAddr = NormalizeSymbolFormat(addressStr);

    // Try to resolve the address/symbol
    duint address = DbgValFromString(normalizedAddr.c_str());

    // If resolution failed (returned 0) and input wasn't "0"
    if (address == 0 && addressStr != "0" && addressStr != "0x0") {
        // Check why it failed and provide helpful error
        if (!DbgIsDebugging()) {
            errorMsg = "Not debugging - load a binary first to resolve symbols";
        } else if (DbgIsRunning()) {
            errorMsg = "Debugger must be paused to resolve symbols. Use pause first.";
        } else {
            // Debugger is paused but symbol not found
            // Check if it looks like a symbol name vs hex address
            bool looksLikeHex = true;
            for (char c : addressStr) {
                if (!isxdigit(c) && c != 'x' && c != 'X') {
                    looksLikeHex = false;
                    break;
                }
            }

            if (looksLikeHex) {
                errorMsg = "Invalid address: " + addressStr;
            } else {
                errorMsg = "Symbol not found: " + addressStr + ". Ensure the module is loaded and try module!symbol format (e.g., kernel32!CreateFileW)";
            }
        }
        return 0;
    }

    return address;
}

// Helper: Build error response for address resolution failure
std::string BuildAddressError(const std::string& errorMsg, const std::string& addressStr) {
    std::stringstream data;
    data << "\"error\":\"" << JsonEscape(errorMsg) << "\"";
    if (!addressStr.empty()) {
        data << ",\"input\":\"" << JsonEscape(addressStr) << "\"";
    }
    return BuildJsonResponse(false, data.str());
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

    // If we're debugging, assume paused (we can only query when paused)
    const char* stateStr = "paused";

    // Get current instruction pointer
    duint cip = DbgValFromString("cip");

    // Get binary path
    char modulePath[MAX_PATH] = "";
    DbgGetModuleAt(cip, modulePath);

    data << "\"state\":\"" << stateStr << "\","
         << "\"current_address\":\"" << std::hex << cip << std::dec << "\","
         << "\"binary_path\":\"" << JsonEscape(modulePath) << "\"";

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

    // Parse and resolve address
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
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

    // Wait for step to complete
    Sleep(100);

    // Get new address
    duint cip = DbgValFromString("cip");
    const char* stateStr = "paused";

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

    // Wait for step to complete
    Sleep(100);

    duint cip = DbgValFromString("cip");
    const char* stateStr = "paused";

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

    // Step out may take longer - wait for completion
    Sleep(500);

    duint cip = DbgValFromString("cip");
    const char* stateStr = "paused";

    std::stringstream data;
    data << "\"address\":\"" << std::hex << cip << std::dec << "\","
         << "\"state\":\"" << stateStr << "\"";

    return BuildJsonResponse(true, data.str());
}

// Handler: SET_BREAKPOINT - Set software breakpoint at address
std::string HandleSetBreakpoint(const std::string& request) {
    // Pre-flight checks with clear error messages
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false,
            "\"error\":\"Not debugging - use x64dbg_load_executable first to start debugging a binary\"");
    }

    if (DbgIsRunning()) {
        return BuildJsonResponse(false,
            "\"error\":\"Debugger is running - use x64dbg_pause first, then set breakpoints while paused\"");
    }

    // Parse address input
    std::string addressStr = ExtractStringField(request, "address");
    if (addressStr.empty()) {
        return BuildJsonResponse(false,
            "\"error\":\"Missing address parameter. Provide a hex address (e.g., 0x401000) or symbol (e.g., kernel32!CreateFileW)\"");
    }

    // Normalize symbol format and resolve address
    std::string normalizedAddr = NormalizeSymbolFormat(addressStr);
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);

    // Check if this looks like a symbol (for fallback logic)
    bool isSymbol = addressStr.find_first_not_of("0123456789abcdefABCDEFxX") != std::string::npos;

    // If direct resolution failed and it looks like a symbol, try bpx command
    // bpx is designed for setting breakpoints on exported symbols
    if (address == 0 && isSymbol) {
        char bpxCmd[512];
        snprintf(bpxCmd, sizeof(bpxCmd), "bpx %s", normalizedAddr.c_str());

        if (DbgCmdExec(bpxCmd)) {
            LogInfo("Breakpoint set on symbol: %s (using bpx)", normalizedAddr.c_str());

            std::stringstream data;
            data << "\"symbol\":\"" << JsonEscape(normalizedAddr) << "\","
                 << "\"method\":\"bpx\","
                 << "\"note\":\"Breakpoint set on exported symbol\"";
            return BuildJsonResponse(true, data.str());
        }

        // bpx also failed - provide helpful error
        std::stringstream errData;
        errData << "\"error\":\"Symbol not found: " << JsonEscape(addressStr) << "\","
                << "\"normalized\":\"" << JsonEscape(normalizedAddr) << "\","
                << "\"suggestions\":["
                << "\"Verify the module is loaded (check with x64dbg_get_modules)\","
                << "\"Use module!function format (e.g., kernel32!CreateFileW)\","
                << "\"Ensure spelling matches exactly (case-sensitive)\","
                << "\"For non-exported functions, use the hex address instead\""
                << "]";
        return BuildJsonResponse(false, errData.str());
    }

    // Direct resolution failed with other error
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    // Set breakpoint using resolved address
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bp %llx", address);

    if (!DbgCmdExec(cmd)) {
        // Try to determine why it failed
        std::stringstream errData;
        errData << "\"error\":\"Failed to set breakpoint at 0x" << std::hex << address << std::dec << "\","
                << "\"possible_causes\":["
                << "\"Breakpoint may already exist at this address\","
                << "\"Address may be in non-executable memory\","
                << "\"Address may be outside mapped memory regions\""
                << "]";
        return BuildJsonResponse(false, errData.str());
    }

    LogInfo("Breakpoint set at 0x%llx", address);

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\"";
    if (isSymbol) {
        data << ",\"symbol\":\"" << JsonEscape(addressStr) << "\"";
        if (normalizedAddr != addressStr) {
            data << ",\"normalized\":\"" << JsonEscape(normalizedAddr) << "\"";
        }
    }

    return BuildJsonResponse(true, data.str());
}

// Handler: DELETE_BREAKPOINT - Delete software breakpoint at address
std::string HandleDeleteBreakpoint(const std::string& request) {
    // Pre-flight checks
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false,
            "\"error\":\"Not debugging - no breakpoints to delete\"");
    }

    if (DbgIsRunning()) {
        return BuildJsonResponse(false,
            "\"error\":\"Debugger is running - use x64dbg_pause first to manage breakpoints\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    if (addressStr.empty()) {
        return BuildJsonResponse(false,
            "\"error\":\"Missing address parameter\"");
    }

    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);

    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bc %llx", address);
    DbgCmdExec(cmd);

    LogInfo("Breakpoint deleted at 0x%llx", address);

    std::stringstream data;
    data << "\"message\":\"Breakpoint deleted\","
         << "\"address\":\"" << std::hex << address << std::dec << "\"";
    return BuildJsonResponse(true, data.str());
}

// Handler: LIST_BREAKPOINTS - List all breakpoints
std::string HandleListBreakpoints(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Get breakpoint list using x64dbg API
    BPMAP bpmap;
    if (!DbgGetBpList(bp_normal, &bpmap)) {
        return BuildJsonResponse(true, "\"breakpoints\":[]");
    }

    std::stringstream data;
    data << "\"breakpoints\":[";

    for (int i = 0; i < bpmap.count; i++) {
        if (i > 0) data << ",";
        data << "{\"address\":\"" << std::hex << bpmap.bp[i].addr << std::dec << "\","
             << "\"enabled\":" << (bpmap.bp[i].enabled ? "true" : "false") << ","
             << "\"type\":\"software\"}";
    }
    data << "]";

    // Free the breakpoint map
    if (bpmap.bp) {
        BridgeFree(bpmap.bp);
    }

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_MODULES - List loaded modules
std::string HandleGetModules(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Use script command to get module info
    // Get main module info as a starting point
    duint mainBase = DbgValFromString("mod.main()");
    char mainPath[MAX_PATH] = "";
    DbgGetModuleAt(mainBase, mainPath);

    std::stringstream data;
    data << "\"modules\":[";

    // Get the main module
    if (mainBase != 0) {
        duint modSize = DbgValFromString("mod.size(mod.main())");
        duint modEntry = DbgValFromString("mod.entry(mod.main())");

        data << "{\"base\":\"" << std::hex << mainBase << std::dec << "\","
             << "\"size\":" << modSize << ","
             << "\"entry\":\"" << std::hex << modEntry << std::dec << "\","
             << "\"path\":\"" << JsonEscape(mainPath) << "\"}";
    }

    data << "]";

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_THREADS - List threads
std::string HandleGetThreads(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Get current thread info using available API
    DWORD currentThreadId = DbgGetThreadId();

    std::stringstream data;
    data << "\"threads\":[";

    // Return at least the current thread
    if (currentThreadId != 0) {
        data << "{\"id\":" << currentThreadId << ","
             << "\"is_current\":true}";
    }

    data << "]";

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_STACK - Get stack trace
std::string HandleGetStack(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Get current RSP and RBP values
    duint rsp = DbgValFromString("rsp");
    duint rbp = DbgValFromString("rbp");
    duint rip = DbgValFromString("rip");
    int count = ExtractIntField(request, "count", 16);

    // Limit count to reasonable range
    if (count < 1) count = 1;
    if (count > 256) count = 256;

    LogInfo("GetStack: RSP=0x%llx, RBP=0x%llx, RIP=0x%llx, count=%d", rsp, rbp, rip, count);

    std::stringstream data;

    // Include current context info
    data << "\"rsp\":\"" << std::hex << rsp << std::dec << "\","
         << "\"rbp\":\"" << std::hex << rbp << std::dec << "\","
         << "\"rip\":\"" << std::hex << rip << std::dec << "\","
         << "\"stack\":[";

    int validEntries = 0;

    // Read stack entries
    for (int i = 0; i < count; i++) {
        duint stackAddr = rsp + (i * sizeof(duint));
        duint stackValue = 0;

        if (!DbgMemRead(stackAddr, &stackValue, sizeof(stackValue))) {
            LogInfo("GetStack: Failed to read at 0x%llx", stackAddr);
            break;
        }

        if (validEntries > 0) data << ",";

        // Try to get module name for the value (if it's a code address)
        char moduleName[MAX_MODULE_SIZE] = "";
        if (DbgMemIsValidReadPtr(stackValue)) {
            DbgGetModuleAt(stackValue, moduleName);
        }

        data << "{\"address\":\"" << std::hex << stackAddr << "\","
             << "\"value\":\"" << std::hex << stackValue << std::dec << "\"";

        // Add module info if available
        if (moduleName[0] != '\0') {
            data << ",\"module\":\"" << JsonEscape(moduleName) << "\"";
        }

        data << "}";
        validEntries++;
    }
    data << "],"
         << "\"count\":" << validEntries;

    LogInfo("GetStack: Returned %d entries", validEntries);

    return BuildJsonResponse(true, data.str());
}

// Handler: DISASSEMBLE - Disassemble instructions at address
std::string HandleDisassemble(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    duint address;

    if (addressStr.empty()) {
        address = DbgValFromString("cip");
    } else {
        std::string errorMsg;
        address = ResolveAddress(addressStr, errorMsg);
        if (address == 0 && !errorMsg.empty()) {
            return BuildAddressError(errorMsg, addressStr);
        }
    }

    int count = ExtractIntField(request, "count", 10);
    if (count < 1) count = 1;
    if (count > 100) count = 100;

    std::stringstream data;
    data << "\"instructions\":[";

    duint currentAddr = address;
    for (int i = 0; i < count; i++) {
        // Check if address is valid
        if (!DbgMemIsValidReadPtr(currentAddr)) {
            break;
        }

        DISASM_INSTR instr = {};
        DbgDisasmAt(currentAddr, &instr);  // Returns void

        // Check if we got valid disassembly
        if (instr.instr_size == 0) {
            break;
        }

        if (i > 0) data << ",";

        // Build instruction string with proper JSON escaping
        std::string instrText = JsonEscape(instr.instruction);

        data << "{\"address\":\"" << std::hex << currentAddr << std::dec << "\","
             << "\"size\":" << instr.instr_size << ","
             << "\"instruction\":\"" << instrText << "\"}";

        currentAddr += instr.instr_size;
    }
    data << "]";

    return BuildJsonResponse(true, data.str());
}

// Handler: WRITE_MEMORY - Write memory to debugged process
std::string HandleWriteMemory(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    std::string dataHex = ExtractStringField(request, "data");

    if (addressStr.empty() || dataHex.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address or data\"");
    }

    // Validate hex data length (max 1MB = 2MB hex chars)
    if (dataHex.length() > 2 * 1024 * 1024) {
        return BuildJsonResponse(false, "\"error\":\"Data too large (max 1MB)\"");
    }

    // Resolve address with detailed error messages
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    // Convert hex string to bytes
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i + 1 < dataHex.length(); i += 2) {
        unsigned int byte;
        if (sscanf(dataHex.c_str() + i, "%02x", &byte) == 1) {
            bytes.push_back(static_cast<unsigned char>(byte));
        }
    }

    if (bytes.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Invalid hex data\"");
    }

    if (!DbgMemWrite(address, bytes.data(), bytes.size())) {
        return BuildJsonResponse(false, "\"error\":\"Failed to write memory\"");
    }

    LogInfo("Wrote %zu bytes to 0x%llx", bytes.size(), address);

    std::stringstream resultData;
    resultData << "\"bytes_written\":" << bytes.size();
    return BuildJsonResponse(true, resultData.str());
}

// Handler: RUN - Continue execution
std::string HandleRun(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    DbgCmdExec("run");

    return BuildJsonResponse(true, "\"message\":\"Execution resumed\"");
}

// Handler: PAUSE - Pause execution
std::string HandlePause(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    DbgCmdExec("pause");

    return BuildJsonResponse(true, "\"message\":\"Execution paused\"");
}

// Handler: SET_REGISTER - Set register value
std::string HandleSetRegister(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string regName = ExtractStringField(request, "register");
    std::string valueStr = ExtractStringField(request, "value");

    if (regName.empty() || valueStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing register or value\"");
    }

    // Validate register name (basic whitelist of common registers)
    // Convert to lowercase for comparison
    std::string regLower = regName;
    for (char& c : regLower) {
        c = tolower(c);
    }

    // Valid x64 general-purpose registers and common segment registers
    static const std::set<std::string> validRegs = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
        "sil", "dil", "bpl", "spl",
        "rflags", "eflags", "flags",
        "cs", "ds", "es", "fs", "gs", "ss"
    };

    if (validRegs.find(regLower) == validRegs.end()) {
        return BuildJsonResponse(false, "\"error\":\"Invalid register name\"");
    }

    // Validate value length (prevent injection)
    if (valueStr.length() > 32) {
        return BuildJsonResponse(false, "\"error\":\"Value too long\"");
    }

    // Use x64dbg command to set register
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "mov %s, %s", regName.c_str(), valueStr.c_str());
    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to set register\"");
    }

    return BuildJsonResponse(true, "\"message\":\"Register set\"");
}

// Handler: GET_MEMORY_MAP - Get memory regions
std::string HandleGetMemoryMap(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Get memory map
    MEMMAP memMap;
    if (!DbgMemMap(&memMap)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to get memory map\"");
    }

    std::stringstream data;
    data << "\"regions\":[";

    for (int i = 0; i < memMap.count; i++) {
        if (i > 0) data << ",";

        MEMPAGE* page = &memMap.page[i];

        // Build protection string
        std::string protStr;
        if (page->mbi.Protect & PAGE_EXECUTE) protStr += "X";
        if (page->mbi.Protect & PAGE_EXECUTE_READ) protStr += "RX";
        if (page->mbi.Protect & PAGE_EXECUTE_READWRITE) protStr += "RWX";
        if (page->mbi.Protect & PAGE_EXECUTE_WRITECOPY) protStr += "WCX";
        if (page->mbi.Protect & PAGE_READONLY) protStr += "R";
        if (page->mbi.Protect & PAGE_READWRITE) protStr += "RW";
        if (page->mbi.Protect & PAGE_WRITECOPY) protStr += "WC";
        if (page->mbi.Protect & PAGE_NOACCESS) protStr += "NA";
        if (protStr.empty()) protStr = "?";

        data << "{\"base\":\"" << std::hex << page->mbi.BaseAddress << std::dec << "\","
             << "\"size\":" << page->mbi.RegionSize << ","
             << "\"protection\":\"" << protStr << "\","
             << "\"info\":\"" << JsonEscape(page->info) << "\"}";
    }
    data << "]";

    // Free the memory map
    if (memMap.page) {
        BridgeFree(memMap.page);
    }

    return BuildJsonResponse(true, data.str());
}

// Handler: EVALUATE_EXPRESSION - Evaluate expression
std::string HandleEvaluateExpression(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string expr = ExtractStringField(request, "expression");
    if (expr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing expression\"");
    }

    duint result = DbgValFromString(expr.c_str());

    std::stringstream data;
    data << "\"result\":\"" << std::hex << result << std::dec << "\","
         << "\"decimal\":" << result;

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_INSTRUCTION - Get single instruction at address
std::string HandleGetInstruction(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    duint address;

    if (addressStr.empty()) {
        address = DbgValFromString("cip");
    } else {
        std::string errorMsg;
        address = ResolveAddress(addressStr, errorMsg);
        if (address == 0 && !errorMsg.empty()) {
            return BuildAddressError(errorMsg, addressStr);
        }
    }

    if (!DbgMemIsValidReadPtr(address)) {
        return BuildJsonResponse(false, "\"error\":\"Invalid address\"");
    }

    DISASM_INSTR instr = {};
    DbgDisasmAt(address, &instr);  // Returns void

    if (instr.instr_size == 0) {
        return BuildJsonResponse(false, "\"error\":\"Failed to disassemble\"");
    }

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\","
         << "\"size\":" << instr.instr_size << ","
         << "\"instruction\":\"" << JsonEscape(instr.instruction) << "\","
         << "\"type\":" << instr.type;

    return BuildJsonResponse(true, data.str());
}

// Handler: SET_COMMENT - Set comment at address
std::string HandleSetComment(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    std::string comment = ExtractStringField(request, "comment");

    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    // Validate comment length (max 2KB)
    if (comment.length() > 2048) {
        return BuildJsonResponse(false, "\"error\":\"Comment too long (max 2KB)\"");
    }

    // Resolve address with detailed error messages
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    if (!DbgSetCommentAt(address, comment.c_str())) {
        return BuildJsonResponse(false, "\"error\":\"Failed to set comment\"");
    }

    return BuildJsonResponse(true, "\"message\":\"Comment set\"");
}

// Handler: GET_COMMENT - Get comment at address
std::string HandleGetComment(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    // Resolve address with detailed error messages
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    char comment[MAX_COMMENT_SIZE] = "";
    DbgGetCommentAt(address, comment);

    std::stringstream data;
    data << "\"comment\":\"" << JsonEscape(comment) << "\"";

    return BuildJsonResponse(true, data.str());
}

// Handler: SKIP_INSTRUCTION - Skip current instruction (move IP forward)
std::string HandleSkipInstruction(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Get current instruction size
    duint cip = DbgValFromString("cip");

    DISASM_INSTR instr = {};
    DbgDisasmAt(cip, &instr);  // Returns void

    if (instr.instr_size == 0) {
        return BuildJsonResponse(false, "\"error\":\"Failed to get instruction size\"");
    }

    // Set RIP/EIP to next instruction
    duint newCip = cip + instr.instr_size;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rip=%llx", newCip);
    DbgCmdExec(cmd);

    std::stringstream data;
    data << "\"old_address\":\"" << std::hex << cip << "\","
         << "\"new_address\":\"" << std::hex << newCip << std::dec << "\","
         << "\"skipped_size\":" << instr.instr_size;

    return BuildJsonResponse(true, data.str());
}

// Handler: RUN_UNTIL_RETURN - Run until return from current function
std::string HandleRunUntilReturn(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Execute "rtr" command (run to return)
    DbgCmdExec("rtr");

    return BuildJsonResponse(true, "\"message\":\"Running until return\"");
}

// Handler: SET_HARDWARE_BREAKPOINT - Set hardware breakpoint
std::string HandleSetHardwareBreakpoint(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    std::string typeStr = ExtractStringField(request, "bp_type");  // "execute", "read", "write", "access"
    int size = ExtractIntField(request, "size", 1);

    // Validate size - hardware breakpoints only support 1, 2, 4, or 8 bytes
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        return BuildJsonResponse(false, "\"error\":\"Invalid size (must be 1, 2, 4, or 8 bytes)\"");
    }

    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    // Map type string to command
    std::string hwType = "x";  // Default: execute
    if (typeStr == "read") hwType = "r";
    else if (typeStr == "write") hwType = "w";
    else if (typeStr == "access") hwType = "a";

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bph %llx, %s, %d", address, hwType.c_str(), size);
    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to set hardware breakpoint\"");
    }

    LogInfo("Hardware breakpoint set at 0x%llx (type: %s, size: %d)", address, hwType.c_str(), size);

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\","
         << "\"type\":\"" << hwType << "\","
         << "\"size\":" << size;

    return BuildJsonResponse(true, data.str());
}

// Handler: SET_MEMORY_BREAKPOINT - Set memory breakpoint
std::string HandleSetMemoryBreakpoint(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    std::string typeStr = ExtractStringField(request, "bp_type");  // "read", "write", "access"

    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    // Map type string to command
    std::string memType = "a";  // Default: access
    if (typeStr == "read") memType = "r";
    else if (typeStr == "write") memType = "w";

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bpm %llx, %s", address, memType.c_str());
    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to set memory breakpoint\"");
    }

    LogInfo("Memory breakpoint set at 0x%llx (type: %s)", address, memType.c_str());

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\","
         << "\"type\":\"" << memType << "\"";

    return BuildJsonResponse(true, data.str());
}

// Handler: DELETE_MEMORY_BREAKPOINT - Delete memory breakpoint
std::string HandleDeleteMemoryBreakpoint(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bpmc %llx", address);
    DbgCmdExec(cmd);

    LogInfo("Memory breakpoint deleted at 0x%llx", address);
    return BuildJsonResponse(true, "\"message\":\"Memory breakpoint deleted\"");
}

// Handler: HIDE_DEBUGGER - Apply anti-anti-debug techniques
std::string HandleHideDebugger(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Use x64dbg's built-in hide debugger functionality
    DbgCmdExec("hide");

    return BuildJsonResponse(true, "\"message\":\"Debugger hidden from target\"");
}

// ============================================================================
// WAIT/SYNCHRONIZATION HANDLERS (Phase 1)
// ============================================================================

// Handler: WAIT_PAUSED - Wait until debugger is paused
std::string HandleWaitPaused(const std::string& request) {
    int timeoutMs = ExtractIntField(request, "timeout", 30000);

    // Cap timeout at 5 minutes
    if (timeoutMs > 300000) timeoutMs = 300000;
    if (timeoutMs < 100) timeoutMs = 100;

    auto startTime = std::chrono::steady_clock::now();
    const int pollInterval = 50;  // Check every 50ms

    while (true) {
        // Check if debugging and paused
        if (DbgIsDebugging() && !DbgIsRunning()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();

            duint cip = DbgValFromString("cip");

            std::stringstream data;
            data << "\"state\":\"paused\","
                 << "\"elapsed_ms\":" << elapsed << ","
                 << "\"current_address\":\"" << std::hex << cip << std::dec << "\"";

            return BuildJsonResponse(true, data.str());
        }

        // Check timeout
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();

        if (elapsed >= timeoutMs) {
            std::stringstream data;
            data << "\"error\":\"Timeout waiting for debugger to pause\","
                 << "\"timeout_ms\":" << timeoutMs << ","
                 << "\"elapsed_ms\":" << elapsed << ","
                 << "\"current_state\":\"" << (DbgIsDebugging() ? (DbgIsRunning() ? "running" : "paused") : "not_debugging") << "\"";

            return BuildJsonResponse(false, data.str());
        }

        // Sleep before next check
        Sleep(pollInterval);
    }
}

// Handler: WAIT_RUNNING - Wait until debugger is running
std::string HandleWaitRunning(const std::string& request) {
    int timeoutMs = ExtractIntField(request, "timeout", 10000);

    // Cap timeout at 5 minutes
    if (timeoutMs > 300000) timeoutMs = 300000;
    if (timeoutMs < 100) timeoutMs = 100;

    auto startTime = std::chrono::steady_clock::now();
    const int pollInterval = 50;

    while (true) {
        // Check if debugging and running
        if (DbgIsDebugging() && DbgIsRunning()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();

            std::stringstream data;
            data << "\"state\":\"running\","
                 << "\"elapsed_ms\":" << elapsed;

            return BuildJsonResponse(true, data.str());
        }

        // Check timeout
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();

        if (elapsed >= timeoutMs) {
            std::stringstream data;
            data << "\"error\":\"Timeout waiting for debugger to run\","
                 << "\"timeout_ms\":" << timeoutMs << ","
                 << "\"elapsed_ms\":" << elapsed << ","
                 << "\"current_state\":\"" << (DbgIsDebugging() ? (DbgIsRunning() ? "running" : "paused") : "not_debugging") << "\"";

            return BuildJsonResponse(false, data.str());
        }

        Sleep(pollInterval);
    }
}

// Handler: WAIT_DEBUGGING - Wait until debugging has started (binary loaded)
std::string HandleWaitDebugging(const std::string& request) {
    int timeoutMs = ExtractIntField(request, "timeout", 30000);

    // Cap timeout at 5 minutes
    if (timeoutMs > 300000) timeoutMs = 300000;
    if (timeoutMs < 100) timeoutMs = 100;

    auto startTime = std::chrono::steady_clock::now();
    const int pollInterval = 50;

    while (true) {
        // Check if debugging
        if (DbgIsDebugging()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();

            std::stringstream data;
            data << "\"state\":\"debugging\","
                 << "\"elapsed_ms\":" << elapsed << ","
                 << "\"is_running\":" << (DbgIsRunning() ? "true" : "false");

            return BuildJsonResponse(true, data.str());
        }

        // Check timeout
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();

        if (elapsed >= timeoutMs) {
            std::stringstream data;
            data << "\"error\":\"Timeout waiting for debugging to start\","
                 << "\"timeout_ms\":" << timeoutMs << ","
                 << "\"elapsed_ms\":" << elapsed << ","
                 << "\"current_state\":\"not_debugging\"";

            return BuildJsonResponse(false, data.str());
        }

        Sleep(pollInterval);
    }
}

// Handler: RESOLVE_SYMBOL - Resolve symbol/expression to address
std::string HandleResolveSymbol(const std::string& request) {
    std::string expression = ExtractStringField(request, "expression");
    if (expression.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing expression\"");
    }

    // Check debugger state for helpful errors
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging - load a binary first\"");
    }

    if (DbgIsRunning()) {
        return BuildJsonResponse(false, "\"error\":\"Debugger must be paused to resolve symbols\"");
    }

    // Try to resolve the expression
    duint address = DbgValFromString(expression.c_str());

    if (address == 0 && expression != "0" && expression != "0x0") {
        // Resolution failed - provide helpful error
        bool looksLikeHex = true;
        for (char c : expression) {
            if (!isxdigit(c) && c != 'x' && c != 'X') {
                looksLikeHex = false;
                break;
            }
        }

        std::stringstream data;
        if (looksLikeHex) {
            data << "\"error\":\"Invalid address: " << JsonEscape(expression) << "\"";
        } else {
            data << "\"error\":\"Symbol not found: " << JsonEscape(expression)
                 << ". Try module!symbol format (e.g., kernel32!CreateFileW)\"";
        }
        data << ",\"expression\":\"" << JsonEscape(expression) << "\"";
        return BuildJsonResponse(false, data.str());
    }

    // Get module name at the address if any
    char moduleName[MAX_MODULE_SIZE] = "";
    DbgGetModuleAt(address, moduleName);

    // Get symbol name at the address if any
    char symbolName[MAX_LABEL_SIZE] = "";
    DbgGetLabelAt(address, SEG_DEFAULT, symbolName);

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\""
         << ",\"expression\":\"" << JsonEscape(expression) << "\"";

    if (strlen(moduleName) > 0) {
        data << ",\"module\":\"" << JsonEscape(moduleName) << "\"";
    }
    if (strlen(symbolName) > 0) {
        data << ",\"symbol\":\"" << JsonEscape(symbolName) << "\"";
    }

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_MODULE_IMPORTS - Get imports for a module
std::string HandleGetModuleImports(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string moduleName = ExtractStringField(request, "module");
    if (moduleName.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing module name\"");
    }

    // Get module base
    duint modBase = DbgModBaseFromName(moduleName.c_str());
    if (modBase == 0) {
        return BuildJsonResponse(false, "\"error\":\"Module not found\"");
    }

    // Note: Full import enumeration requires more complex PE parsing
    // For now, return basic info
    std::stringstream data;
    data << "\"module\":\"" << moduleName << "\","
         << "\"base\":\"" << std::hex << modBase << std::dec << "\","
         << "\"imports\":[]";  // TODO: Implement full import enumeration

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_MODULE_EXPORTS - Get exports for a module
std::string HandleGetModuleExports(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string moduleName = ExtractStringField(request, "module");
    if (moduleName.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing module name\"");
    }

    // Get module base
    duint modBase = DbgModBaseFromName(moduleName.c_str());
    if (modBase == 0) {
        return BuildJsonResponse(false, "\"error\":\"Module not found\"");
    }

    // Note: Full export enumeration requires more complex PE parsing
    // For now, return basic info
    std::stringstream data;
    data << "\"module\":\"" << moduleName << "\","
         << "\"base\":\"" << std::hex << modBase << std::dec << "\","
         << "\"exports\":[]";  // TODO: Implement full export enumeration

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_MEMORY_INFO - Get info about specific memory region
std::string HandleGetMemoryInfo(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    // Resolve address with detailed error messages
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    // Query memory info
    MEMORY_BASIC_INFORMATION mbi;
    if (!DbgMemIsValidReadPtr(address)) {
        return BuildJsonResponse(false, "\"error\":\"Invalid memory address\"");
    }

    // Get module at address if any
    char moduleName[MAX_MODULE_SIZE] = "";
    DbgGetModuleAt(address, moduleName);

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\","
         << "\"module\":\"" << JsonEscape(moduleName) << "\","
         << "\"readable\":" << (DbgMemIsValidReadPtr(address) ? "true" : "false");

    return BuildJsonResponse(true, data.str());
}

// ============================================================================
// MEMORY ALLOCATION HANDLERS (Phase 3)
// ============================================================================

// Handler: VIRT_ALLOC - Allocate memory in debugee's address space
std::string HandleVirtAlloc(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    int size = ExtractIntField(request, "size", 4096);  // Default: 4KB (one page)
    std::string addressStr = ExtractStringField(request, "address");
    duint preferredAddr = addressStr.empty() ? 0 : DbgValFromString(addressStr.c_str());

    // Validate size (max 16MB)
    if (size <= 0 || size > 16 * 1024 * 1024) {
        return BuildJsonResponse(false, "\"error\":\"Invalid size (must be 1 to 16MB)\"");
    }

    // Use VirtualAllocEx via x64dbg command
    // Format: alloc size [, address]
    char cmd[256];
    if (preferredAddr != 0) {
        snprintf(cmd, sizeof(cmd), "alloc %d, %llx", size, preferredAddr);
    } else {
        snprintf(cmd, sizeof(cmd), "alloc %d", size);
    }

    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to allocate memory\"");
    }

    // Get the result from $result register
    duint allocatedAddr = DbgValFromString("$result");

    if (allocatedAddr == 0) {
        return BuildJsonResponse(false, "\"error\":\"VirtualAllocEx returned NULL\"");
    }

    LogInfo("Allocated %d bytes at 0x%llx", size, allocatedAddr);

    std::stringstream data;
    data << "\"address\":\"" << std::hex << allocatedAddr << std::dec << "\","
         << "\"size\":" << size;

    return BuildJsonResponse(true, data.str());
}

// Handler: VIRT_FREE - Free memory in debugee's address space
std::string HandleVirtFree(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    // Resolve address with detailed error messages
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    // Use free command
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "free %llx", address);

    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to free memory\"");
    }

    LogInfo("Freed memory at 0x%llx", address);
    return BuildJsonResponse(true, "\"message\":\"Memory freed\"");
}

// Handler: VIRT_PROTECT - Change memory protection
std::string HandleVirtProtect(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    std::string protectionStr = ExtractStringField(request, "protection");
    int size = ExtractIntField(request, "size", 4096);

    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    // Validate size (max 16MB - same as VirtAlloc)
    if (size <= 0 || size > 16 * 1024 * 1024) {
        return BuildJsonResponse(false, "\"error\":\"Invalid size (must be 1 to 16MB)\"");
    }

    // Resolve address with detailed error messages
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    // Map protection string to Windows constants
    // Common values: "rwx", "rx", "rw", "r", "x", "wx"
    DWORD protection = PAGE_READWRITE;  // Default
    if (protectionStr == "rwx" || protectionStr == "RWX") {
        protection = PAGE_EXECUTE_READWRITE;
    } else if (protectionStr == "rx" || protectionStr == "RX") {
        protection = PAGE_EXECUTE_READ;
    } else if (protectionStr == "rw" || protectionStr == "RW") {
        protection = PAGE_READWRITE;
    } else if (protectionStr == "r" || protectionStr == "R") {
        protection = PAGE_READONLY;
    } else if (protectionStr == "x" || protectionStr == "X") {
        protection = PAGE_EXECUTE;
    } else if (protectionStr == "wx" || protectionStr == "WX") {
        protection = PAGE_EXECUTE_WRITECOPY;
    } else if (protectionStr == "n" || protectionStr == "N" || protectionStr == "none") {
        protection = PAGE_NOACCESS;
    }

    // Use setpagerights command (x64dbg specific)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "setpagerights %llx, %d, %x", address, size, protection);

    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to change memory protection\"");
    }

    LogInfo("Changed protection at 0x%llx to 0x%x", address, protection);

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\","
         << "\"protection\":" << protection;

    return BuildJsonResponse(true, data.str());
}

// Handler: MEM_SET - Fill memory with a value
std::string HandleMemSet(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    int value = ExtractIntField(request, "value", 0);
    int size = ExtractIntField(request, "size", 0);

    if (addressStr.empty() || size <= 0) {
        return BuildJsonResponse(false, "\"error\":\"Missing address or invalid size\"");
    }

    // Validate size (max 1MB)
    if (size > 1024 * 1024) {
        return BuildJsonResponse(false, "\"error\":\"Size too large (max 1MB)\"");
    }

    // Resolve address with detailed error messages
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    // Create buffer with repeated value
    std::vector<unsigned char> buffer(size, static_cast<unsigned char>(value & 0xFF));

    // Write to memory
    if (!DbgMemWrite(address, buffer.data(), size)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to write memory\"");
    }

    LogInfo("Filled %d bytes at 0x%llx with 0x%02x", size, address, value & 0xFF);

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\","
         << "\"size\":" << size << ","
         << "\"value\":" << (value & 0xFF);

    return BuildJsonResponse(true, data.str());
}

// Handler: CHECK_VALID_PTR - Check if address is readable
std::string HandleCheckValidPtr(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    // Note: For CHECK_VALID_PTR we allow 0 to return as "not valid"
    // so we don't use the full ResolveAddress with error checking
    duint address = DbgValFromString(addressStr.c_str());

    bool isValid = DbgMemIsValidReadPtr(address);

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\","
         << "\"valid\":" << (isValid ? "true" : "false");

    return BuildJsonResponse(true, data.str());
}

// ============================================================================
// ENHANCED BREAKPOINT HANDLERS (Phase 3)
// ============================================================================

// Handler: TOGGLE_BREAKPOINT - Enable/disable software breakpoint
std::string HandleToggleBreakpoint(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    int enable = ExtractIntField(request, "enable", 1);  // Default: enable

    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    // Resolve address with detailed error messages
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    // Use bpe (breakpoint enable) or bpd (breakpoint disable)
    char cmd[256];
    if (enable) {
        snprintf(cmd, sizeof(cmd), "bpe %llx", address);
    } else {
        snprintf(cmd, sizeof(cmd), "bpd %llx", address);
    }

    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to toggle breakpoint\"");
    }

    LogInfo("Breakpoint at 0x%llx %s", address, enable ? "enabled" : "disabled");

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\","
         << "\"enabled\":" << (enable ? "true" : "false");

    return BuildJsonResponse(true, data.str());
}

// Handler: DELETE_HARDWARE_BREAKPOINT - Delete hardware breakpoint
std::string HandleDeleteHardwareBreakpoint(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    // Resolve address with detailed error messages
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bphc %llx", address);
    DbgCmdExec(cmd);

    LogInfo("Hardware breakpoint deleted at 0x%llx", address);
    return BuildJsonResponse(true, "\"message\":\"Hardware breakpoint deleted\"");
}

// Handler: TOGGLE_HARDWARE_BREAKPOINT - Enable/disable hardware breakpoint
std::string HandleToggleHardwareBreakpoint(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    int enable = ExtractIntField(request, "enable", 1);

    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    // Resolve address with detailed error messages
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    char cmd[256];
    if (enable) {
        snprintf(cmd, sizeof(cmd), "bphe %llx", address);
    } else {
        snprintf(cmd, sizeof(cmd), "bphd %llx", address);
    }

    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to toggle hardware breakpoint\"");
    }

    LogInfo("Hardware breakpoint at 0x%llx %s", address, enable ? "enabled" : "disabled");

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\","
         << "\"enabled\":" << (enable ? "true" : "false");

    return BuildJsonResponse(true, data.str());
}

// Handler: TOGGLE_MEMORY_BREAKPOINT - Enable/disable memory breakpoint
std::string HandleToggleMemoryBreakpoint(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    int enable = ExtractIntField(request, "enable", 1);

    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    // Resolve address with detailed error messages
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    char cmd[256];
    if (enable) {
        snprintf(cmd, sizeof(cmd), "bpme %llx", address);
    } else {
        snprintf(cmd, sizeof(cmd), "bpmd %llx", address);
    }

    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to toggle memory breakpoint\"");
    }

    LogInfo("Memory breakpoint at 0x%llx %s", address, enable ? "enabled" : "disabled");

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\","
         << "\"enabled\":" << (enable ? "true" : "false");

    return BuildJsonResponse(true, data.str());
}

// Handler: LIST_ALL_BREAKPOINTS - List all breakpoints (software, hardware, memory)
std::string HandleListAllBreakpoints(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::stringstream data;
    data << "\"breakpoints\":{";

    // Software breakpoints
    {
        BPMAP bpmap;
        data << "\"software\":[";
        if (DbgGetBpList(bp_normal, &bpmap)) {
            for (int i = 0; i < bpmap.count; i++) {
                if (i > 0) data << ",";
                data << "{\"address\":\"" << std::hex << bpmap.bp[i].addr << std::dec << "\","
                     << "\"enabled\":" << (bpmap.bp[i].enabled ? "true" : "false") << ","
                     << "\"singleshoot\":" << (bpmap.bp[i].singleshoot ? "true" : "false") << "}";
            }
            if (bpmap.bp) BridgeFree(bpmap.bp);
        }
        data << "],";
    }

    // Hardware breakpoints
    {
        BPMAP bpmap;
        data << "\"hardware\":[";
        if (DbgGetBpList(bp_hardware, &bpmap)) {
            for (int i = 0; i < bpmap.count; i++) {
                if (i > 0) data << ",";

                // Map hardware type
                const char* hwType = "unknown";
                switch (bpmap.bp[i].hwSize) {
                    case 0: hwType = "execute"; break;
                    case 1: hwType = "write"; break;
                    case 2: hwType = "io"; break;
                    case 3: hwType = "access"; break;
                }

                data << "{\"address\":\"" << std::hex << bpmap.bp[i].addr << std::dec << "\","
                     << "\"enabled\":" << (bpmap.bp[i].enabled ? "true" : "false") << ","
                     << "\"type\":\"" << hwType << "\","
                     << "\"size\":" << (1 << bpmap.bp[i].hwSize) << "}";
            }
            if (bpmap.bp) BridgeFree(bpmap.bp);
        }
        data << "],";
    }

    // Memory breakpoints
    {
        BPMAP bpmap;
        data << "\"memory\":[";
        if (DbgGetBpList(bp_memory, &bpmap)) {
            for (int i = 0; i < bpmap.count; i++) {
                if (i > 0) data << ",";

                // Map memory type
                const char* memType = "access";
                if (bpmap.bp[i].type == bp_memory) {
                    // Memory breakpoint type is stored differently
                    memType = "access";  // Default for now
                }

                data << "{\"address\":\"" << std::hex << bpmap.bp[i].addr << std::dec << "\","
                     << "\"enabled\":" << (bpmap.bp[i].enabled ? "true" : "false") << ","
                     << "\"type\":\"" << memType << "\"}";
            }
            if (bpmap.bp) BridgeFree(bpmap.bp);
        }
        data << "]";
    }

    data << "}";

    return BuildJsonResponse(true, data.str());
}

// ============================================================================
// PHASE 4: TRACING HANDLERS
// ============================================================================

// Handler: START_TRACE - Start instruction tracing
std::string HandleStartTrace(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    InitTraceLocks();
    EnterCriticalSection(&g_traceLock);

    // Parse options
    g_traceState.traceInto = ExtractIntField(request, "trace_into", 1) != 0;
    g_traceState.maxEntries = ExtractIntField(request, "max_entries", 100000);
    std::string logFile = ExtractStringField(request, "log_file");

    // Cap max entries
    if (g_traceState.maxEntries > 1000000) g_traceState.maxEntries = 1000000;

    // Clear previous trace
    g_traceState.entries.clear();
    g_traceState.startTime = GetTickCount64();
    g_traceState.enabled = true;

    // Open log file if specified
    if (!logFile.empty()) {
        g_traceState.logFile = logFile;
        g_traceState.logFileHandle = fopen(logFile.c_str(), "w");
        if (g_traceState.logFileHandle) {
            fprintf(g_traceState.logFileHandle, "# Trace started at %llu\n", g_traceState.startTime);
            fprintf(g_traceState.logFileHandle, "# Format: timestamp,address,module,instruction,thread_id\n");
        }
    }

    LeaveCriticalSection(&g_traceLock);

    LogInfo("Trace started (trace_into=%d, max=%llu)", g_traceState.traceInto, g_traceState.maxEntries);

    std::stringstream data;
    data << "\"message\":\"Trace started\","
         << "\"trace_into\":" << (g_traceState.traceInto ? "true" : "false") << ","
         << "\"max_entries\":" << g_traceState.maxEntries;

    return BuildJsonResponse(true, data.str());
}

// Handler: STOP_TRACE - Stop instruction tracing
std::string HandleStopTrace(const std::string& request) {
    InitTraceLocks();
    EnterCriticalSection(&g_traceLock);

    g_traceState.enabled = false;

    uint64_t entryCount = g_traceState.entries.size();
    uint64_t duration = GetTickCount64() - g_traceState.startTime;

    // Close log file
    if (g_traceState.logFileHandle) {
        fprintf(g_traceState.logFileHandle, "# Trace stopped. Total entries: %llu, Duration: %llu ms\n",
                entryCount, duration);
        fclose(g_traceState.logFileHandle);
        g_traceState.logFileHandle = nullptr;
    }

    LeaveCriticalSection(&g_traceLock);

    LogInfo("Trace stopped (%llu entries, %llu ms)", entryCount, duration);

    std::stringstream data;
    data << "\"message\":\"Trace stopped\","
         << "\"entries\":" << entryCount << ","
         << "\"duration_ms\":" << duration;

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_TRACE_DATA - Get trace data
std::string HandleGetTraceData(const std::string& request) {
    InitTraceLocks();
    EnterCriticalSection(&g_traceLock);

    int offset = ExtractIntField(request, "offset", 0);
    int limit = ExtractIntField(request, "limit", 1000);

    // Cap limit
    if (limit > 10000) limit = 10000;
    if (limit < 1) limit = 1;

    std::stringstream data;
    data << "\"total\":" << g_traceState.entries.size() << ","
         << "\"offset\":" << offset << ","
         << "\"enabled\":" << (g_traceState.enabled ? "true" : "false") << ","
         << "\"entries\":[";

    int count = 0;
    for (size_t i = offset; i < g_traceState.entries.size() && count < limit; i++, count++) {
        if (count > 0) data << ",";

        const TraceEntry& entry = g_traceState.entries[i];
        data << "{\"address\":\"" << std::hex << entry.address << std::dec << "\","
             << "\"timestamp\":" << entry.timestamp << ","
             << "\"instruction\":\"" << JsonEscape(entry.instruction) << "\","
             << "\"module\":\"" << JsonEscape(entry.module) << "\","
             << "\"thread_id\":" << entry.threadId << "}";
    }
    data << "]";

    LeaveCriticalSection(&g_traceLock);

    return BuildJsonResponse(true, data.str());
}

// Handler: CLEAR_TRACE - Clear trace data
std::string HandleClearTrace(const std::string& request) {
    InitTraceLocks();
    EnterCriticalSection(&g_traceLock);

    g_traceState.entries.clear();

    LeaveCriticalSection(&g_traceLock);

    return BuildJsonResponse(true, "\"message\":\"Trace data cleared\"");
}

// Handler: SET_API_BREAKPOINT - Set breakpoint on API function with logging
std::string HandleSetApiBreakpoint(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string apiName = ExtractStringField(request, "api_name");
    if (apiName.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing api_name\"");
    }

    // Resolve the API address
    std::string errorMsg;
    duint address = ResolveAddress(apiName, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, apiName);
    }

    // Set conditional breakpoint with logging
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "bp %llx", address);
    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to set breakpoint\"");
    }

    // Add to watched APIs
    InitTraceLocks();
    EnterCriticalSection(&g_apiLogLock);
    g_apiLogState.watchedApis.insert(apiName);
    g_apiLogState.enabled = true;
    if (g_apiLogState.startTime == 0) {
        g_apiLogState.startTime = GetTickCount64();
    }
    LeaveCriticalSection(&g_apiLogLock);

    LogInfo("API breakpoint set: %s at 0x%llx", apiName.c_str(), address);

    std::stringstream data;
    data << "\"api_name\":\"" << JsonEscape(apiName) << "\","
         << "\"address\":\"" << std::hex << address << std::dec << "\"";

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_API_LOG - Get API call log
std::string HandleGetApiLog(const std::string& request) {
    InitTraceLocks();
    EnterCriticalSection(&g_apiLogLock);

    int offset = ExtractIntField(request, "offset", 0);
    int limit = ExtractIntField(request, "limit", 100);

    if (limit > 1000) limit = 1000;
    if (limit < 1) limit = 1;

    std::stringstream data;
    data << "\"total\":" << g_apiLogState.entries.size() << ","
         << "\"offset\":" << offset << ","
         << "\"enabled\":" << (g_apiLogState.enabled ? "true" : "false") << ","
         << "\"entries\":[";

    int count = 0;
    for (size_t i = offset; i < g_apiLogState.entries.size() && count < limit; i++, count++) {
        if (count > 0) data << ",";

        const ApiCallEntry& entry = g_apiLogState.entries[i];
        data << "{\"id\":" << entry.id << ","
             << "\"address\":\"" << std::hex << entry.address << std::dec << "\","
             << "\"return_address\":\"" << std::hex << entry.returnAddress << std::dec << "\","
             << "\"timestamp\":" << entry.timestamp << ","
             << "\"api_name\":\"" << JsonEscape(entry.apiName) << "\","
             << "\"module\":\"" << JsonEscape(entry.moduleName) << "\","
             << "\"thread_id\":" << entry.threadId << ","
             << "\"args\":[";

        for (size_t j = 0; j < entry.args.size(); j++) {
            if (j > 0) data << ",";
            data << "\"" << std::hex << entry.args[j] << std::dec << "\"";
        }
        data << "]}";
    }
    data << "]";

    LeaveCriticalSection(&g_apiLogLock);

    return BuildJsonResponse(true, data.str());
}

// Handler: CLEAR_API_LOG - Clear API call log
std::string HandleClearApiLog(const std::string& request) {
    InitTraceLocks();
    EnterCriticalSection(&g_apiLogLock);

    g_apiLogState.entries.clear();
    g_apiLogState.nextId = 1;

    LeaveCriticalSection(&g_apiLogLock);

    return BuildJsonResponse(true, "\"message\":\"API log cleared\"");
}

// ============================================================================
// PHASE 4: STRING & PATTERN SEARCH HANDLERS
// ============================================================================

// Handler: FIND_STRINGS - Search for strings in memory
std::string HandleFindStrings(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    int size = ExtractIntField(request, "size", 0x10000);  // Default 64KB
    int minLength = ExtractIntField(request, "min_length", 4);
    bool searchAscii = ExtractIntField(request, "ascii", 1) != 0;
    bool searchUnicode = ExtractIntField(request, "unicode", 1) != 0;

    // Validate
    if (size > 10 * 1024 * 1024) {
        return BuildJsonResponse(false, "\"error\":\"Size too large (max 10MB)\"");
    }
    if (minLength < 2) minLength = 2;
    if (minLength > 100) minLength = 100;

    // Resolve start address
    duint startAddr;
    if (addressStr.empty()) {
        // Use main module base if no address specified
        startAddr = DbgValFromString("mod.main()");
    } else {
        std::string errorMsg;
        startAddr = ResolveAddress(addressStr, errorMsg);
        if (startAddr == 0 && !errorMsg.empty()) {
            return BuildAddressError(errorMsg, addressStr);
        }
    }

    // Read memory
    std::vector<unsigned char> buffer(size);
    if (!DbgMemRead(startAddr, buffer.data(), size)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to read memory\"");
    }

    // Find strings
    std::vector<std::pair<duint, std::string>> foundStrings;
    const int maxStrings = 1000;

    // Search for ASCII strings
    if (searchAscii && foundStrings.size() < maxStrings) {
        size_t start = 0;
        while (start < buffer.size() && foundStrings.size() < maxStrings) {
            // Find start of printable sequence
            while (start < buffer.size() && (buffer[start] < 0x20 || buffer[start] > 0x7E)) {
                start++;
            }

            if (start >= buffer.size()) break;

            // Find end of printable sequence
            size_t end = start;
            while (end < buffer.size() && buffer[end] >= 0x20 && buffer[end] <= 0x7E) {
                end++;
            }

            // Check length
            if (end - start >= (size_t)minLength) {
                std::string str(buffer.begin() + start, buffer.begin() + end);
                foundStrings.push_back({startAddr + start, str});
            }

            start = end + 1;
        }
    }

    // Search for Unicode (UTF-16LE) strings
    if (searchUnicode && foundStrings.size() < maxStrings) {
        for (size_t i = 0; i + 1 < buffer.size() && foundStrings.size() < maxStrings; i += 2) {
            // Check for printable UTF-16LE character (ASCII range with null high byte)
            if (buffer[i] >= 0x20 && buffer[i] <= 0x7E && buffer[i + 1] == 0) {
                size_t start = i;
                std::string str;

                // Collect characters
                while (i + 1 < buffer.size() && buffer[i] >= 0x20 && buffer[i] <= 0x7E && buffer[i + 1] == 0) {
                    str += (char)buffer[i];
                    i += 2;
                }

                if (str.length() >= (size_t)minLength) {
                    foundStrings.push_back({startAddr + start, str});
                }
            }
        }
    }

    // Build response
    std::stringstream data;
    data << "\"count\":" << foundStrings.size() << ","
         << "\"strings\":[";

    for (size_t i = 0; i < foundStrings.size(); i++) {
        if (i > 0) data << ",";
        data << "{\"address\":\"" << std::hex << foundStrings[i].first << std::dec << "\","
             << "\"value\":\"" << JsonEscape(foundStrings[i].second) << "\","
             << "\"length\":" << foundStrings[i].second.length() << "}";
    }
    data << "]";

    return BuildJsonResponse(true, data.str());
}

// Handler: PATTERN_SCAN - Search for byte pattern with wildcards
std::string HandlePatternScan(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string pattern = ExtractStringField(request, "pattern");
    std::string addressStr = ExtractStringField(request, "address");
    int size = ExtractIntField(request, "size", 0x100000);  // Default 1MB

    if (pattern.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing pattern\"");
    }

    // Validate size
    if (size > 100 * 1024 * 1024) {
        return BuildJsonResponse(false, "\"error\":\"Size too large (max 100MB)\"");
    }

    // Parse pattern - format: "90 ?? E8 ?? ?? ?? ??" or "90??E8??????"
    std::vector<std::pair<unsigned char, bool>> parsedPattern;  // (byte, isWildcard)

    std::string cleanPattern;
    for (char c : pattern) {
        if (isxdigit(c) || c == '?') {
            cleanPattern += toupper(c);
        }
    }

    if (cleanPattern.length() % 2 != 0) {
        return BuildJsonResponse(false, "\"error\":\"Invalid pattern length\"");
    }

    for (size_t i = 0; i < cleanPattern.length(); i += 2) {
        if (cleanPattern[i] == '?' || cleanPattern[i + 1] == '?') {
            parsedPattern.push_back({0, true});  // Wildcard
        } else {
            unsigned int byte;
            sscanf(cleanPattern.c_str() + i, "%02X", &byte);
            parsedPattern.push_back({(unsigned char)byte, false});
        }
    }

    if (parsedPattern.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Empty pattern\"");
    }

    // Resolve start address
    duint startAddr;
    if (addressStr.empty()) {
        startAddr = DbgValFromString("mod.main()");
    } else {
        std::string errorMsg;
        startAddr = ResolveAddress(addressStr, errorMsg);
        if (startAddr == 0 && !errorMsg.empty()) {
            return BuildAddressError(errorMsg, addressStr);
        }
    }

    // Read memory
    std::vector<unsigned char> buffer(size);
    duint bytesRead = 0;
    DbgMemRead(startAddr, buffer.data(), size);

    // Search for pattern
    std::vector<duint> matches;
    const int maxMatches = 100;

    for (size_t i = 0; i + parsedPattern.size() <= buffer.size() && matches.size() < maxMatches; i++) {
        bool match = true;
        for (size_t j = 0; j < parsedPattern.size(); j++) {
            if (!parsedPattern[j].second && buffer[i + j] != parsedPattern[j].first) {
                match = false;
                break;
            }
        }
        if (match) {
            matches.push_back(startAddr + i);
        }
    }

    // Build response
    std::stringstream data;
    data << "\"count\":" << matches.size() << ","
         << "\"pattern\":\"" << JsonEscape(pattern) << "\","
         << "\"matches\":[";

    for (size_t i = 0; i < matches.size(); i++) {
        if (i > 0) data << ",";
        data << "\"" << std::hex << matches[i] << std::dec << "\"";
    }
    data << "]";

    return BuildJsonResponse(true, data.str());
}

// Handler: XOR_DECRYPT - Try XOR decryption on memory region
std::string HandleXorDecrypt(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    int size = ExtractIntField(request, "size", 256);
    std::string keyStr = ExtractStringField(request, "key");
    bool tryAllSingleByte = ExtractIntField(request, "try_all", 0) != 0;

    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    // Validate size
    if (size > 1024 * 1024) {
        return BuildJsonResponse(false, "\"error\":\"Size too large (max 1MB)\"");
    }
    if (size < 1) size = 1;

    // Resolve address
    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    // Read memory
    std::vector<unsigned char> buffer(size);
    if (!DbgMemRead(address, buffer.data(), size)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to read memory\"");
    }

    // Parse key if provided
    std::vector<unsigned char> key;
    if (!keyStr.empty()) {
        // Try hex interpretation first
        std::string cleanKey;
        for (char c : keyStr) {
            if (isxdigit(c)) cleanKey += c;
        }

        if (cleanKey.length() >= 2) {
            for (size_t i = 0; i + 1 < cleanKey.length(); i += 2) {
                unsigned int byte;
                sscanf(cleanKey.c_str() + i, "%02x", &byte);
                key.push_back((unsigned char)byte);
            }
        } else {
            // Use as ASCII key
            for (char c : keyStr) {
                key.push_back((unsigned char)c);
            }
        }
    }

    std::stringstream data;

    if (tryAllSingleByte) {
        // Try all single-byte XOR keys and show results with printable strings
        data << "\"results\":[";

        int resultsCount = 0;
        for (int k = 1; k < 256 && resultsCount < 50; k++) {
            std::string decrypted;
            int printableCount = 0;

            for (size_t i = 0; i < buffer.size(); i++) {
                unsigned char c = buffer[i] ^ k;
                if (c >= 0x20 && c <= 0x7E) {
                    printableCount++;
                    decrypted += (char)c;
                } else if (c == 0) {
                    decrypted += "\\0";
                } else {
                    decrypted += '.';
                }
            }

            // Only include if >50% printable
            if (printableCount * 2 > (int)buffer.size()) {
                if (resultsCount > 0) data << ",";
                data << "{\"key\":\"0x" << std::hex << k << std::dec << "\","
                     << "\"printable_percent\":" << (printableCount * 100 / buffer.size()) << ","
                     << "\"preview\":\"" << JsonEscape(decrypted.substr(0, 100)) << "\"}";
                resultsCount++;
            }
        }
        data << "]";
    } else if (!key.empty()) {
        // XOR with provided key
        std::string decrypted;
        std::string hexResult;

        for (size_t i = 0; i < buffer.size(); i++) {
            unsigned char c = buffer[i] ^ key[i % key.size()];
            if (c >= 0x20 && c <= 0x7E) {
                decrypted += (char)c;
            } else if (c == 0) {
                decrypted += "\\0";
            } else {
                decrypted += '.';
            }

            char hex[4];
            snprintf(hex, sizeof(hex), "%02x", c);
            hexResult += hex;
        }

        data << "\"key\":\"" << JsonEscape(keyStr) << "\","
             << "\"decrypted_hex\":\"" << hexResult << "\","
             << "\"decrypted_ascii\":\"" << JsonEscape(decrypted) << "\"";
    } else {
        return BuildJsonResponse(false, "\"error\":\"Provide a key or set try_all=1\"");
    }

    return BuildJsonResponse(true, data.str());
}

// Handler: FIND_REFERENCES - Find references to an address
std::string HandleFindReferences(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    std::string errorMsg;
    duint targetAddr = ResolveAddress(addressStr, errorMsg);
    if (targetAddr == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    // Use x64dbg's reference search
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "findallmem %llx", targetAddr);

    // Get references using DbgGetRefList
    // Note: This is a simplified implementation - full implementation would use GUIREF APIs
    std::stringstream data;
    data << "\"target\":\"" << std::hex << targetAddr << std::dec << "\","
         << "\"message\":\"Use GUI for full reference search - API returns limited results\","
         << "\"references\":[]";

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_CALL_STACK_DETAILED - Get detailed call stack with symbols
std::string HandleGetCallStackDetailed(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Get current RSP/ESP and RIP/EIP
    duint rsp = DbgValFromString("rsp");
    duint rip = DbgValFromString("rip");

    if (rsp == 0) {
        return BuildJsonResponse(false, "\"error\":\"Failed to get stack pointer\"");
    }

    std::stringstream data;
    std::vector<std::pair<duint, duint>> frames;  // (return_addr, frame_ptr)

    // Add current instruction as first frame
    frames.push_back({rip, rsp});

    // Walk stack looking for return addresses
    // Simple heuristic: read potential return addresses from stack
    const int maxFrames = 50;
    const int stackScanSize = 0x1000;  // Scan 4KB of stack

    std::vector<duint> stackData(stackScanSize / sizeof(duint));
    if (DbgMemRead(rsp, stackData.data(), stackScanSize)) {
        for (size_t i = 0; i < stackData.size() && frames.size() < maxFrames; i++) {
            duint potentialAddr = stackData[i];

            // Check if this looks like a valid code address
            if (potentialAddr != 0 && DbgMemIsValidReadPtr(potentialAddr)) {
                char moduleName[MAX_MODULE_SIZE] = "";
                if (DbgGetModuleAt(potentialAddr, moduleName) && moduleName[0] != '\0') {
                    // It's in a module, likely a return address
                    frames.push_back({potentialAddr, rsp + i * sizeof(duint)});
                }
            }
        }
    }

    data << "\"depth\":" << frames.size() << ","
         << "\"frames\":[";

    for (size_t i = 0; i < frames.size(); i++) {
        if (i > 0) data << ",";

        duint addr = frames[i].first;
        duint framePtr = frames[i].second;

        // Get symbol info
        char symbolName[MAX_LABEL_SIZE] = "";
        DbgGetLabelAt(addr, SEG_DEFAULT, symbolName);

        char moduleName[MAX_MODULE_SIZE] = "";
        DbgGetModuleAt(addr, moduleName);

        data << "{\"address\":\"" << std::hex << addr << std::dec << "\","
             << "\"frame_ptr\":\"" << std::hex << framePtr << std::dec << "\","
             << "\"symbol\":\"" << JsonEscape(symbolName) << "\","
             << "\"module\":\"" << JsonEscape(moduleName) << "\"}";
    }
    data << "]";

    return BuildJsonResponse(true, data.str());
}

// ============================================================================
// PHASE 5: ANTI-DEBUG BYPASS HANDLERS
// ============================================================================

// Handler: HIDE_DEBUG_PEB - Patch PEB to hide debugger
std::string HandleHideDebugPeb(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    // Get PEB address
    duint pebAddr = DbgValFromString("peb()");
    if (pebAddr == 0) {
        return BuildJsonResponse(false, "\"error\":\"Failed to get PEB address\"");
    }

    bool success = true;
    std::stringstream details;
    details << "\"patches\":[";
    int patchCount = 0;

    // Patch BeingDebugged (PEB+0x2)
    unsigned char beingDebugged = 0;
    if (DbgMemRead(pebAddr + 0x2, &beingDebugged, 1)) {
        if (beingDebugged != 0) {
            unsigned char zero = 0;
            if (DbgMemWrite(pebAddr + 0x2, &zero, 1)) {
                if (patchCount > 0) details << ",";
                details << "{\"field\":\"BeingDebugged\",\"offset\":\"0x2\",\"old\":" << (int)beingDebugged << ",\"new\":0}";
                patchCount++;
                g_antiDebugState.pebPatched = true;
            }
        }
    }

    // Patch NtGlobalFlag (PEB+0x68 for x86, PEB+0xBC for x64)
#ifdef _WIN64
    duint ntGlobalFlagOffset = 0xBC;
#else
    duint ntGlobalFlagOffset = 0x68;
#endif

    uint32_t ntGlobalFlag = 0;
    if (DbgMemRead(pebAddr + ntGlobalFlagOffset, &ntGlobalFlag, 4)) {
        // Debug flags: FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20) | FLG_HEAP_VALIDATE_PARAMETERS (0x40)
        uint32_t debugFlags = 0x70;
        if (ntGlobalFlag & debugFlags) {
            uint32_t newFlag = ntGlobalFlag & ~debugFlags;
            if (DbgMemWrite(pebAddr + ntGlobalFlagOffset, &newFlag, 4)) {
                if (patchCount > 0) details << ",";
                details << "{\"field\":\"NtGlobalFlag\",\"offset\":\"0x" << std::hex << ntGlobalFlagOffset << std::dec
                        << "\",\"old\":\"0x" << std::hex << ntGlobalFlag << "\",\"new\":\"0x" << newFlag << std::dec << "\"}";
                patchCount++;
                g_antiDebugState.ntGlobalFlagPatched = true;
            }
        }
    }

    details << "]";

    LogInfo("PEB anti-debug patched: %d fields modified", patchCount);

    std::stringstream data;
    data << "\"message\":\"PEB anti-debug bypassed\","
         << "\"peb_address\":\"" << std::hex << pebAddr << std::dec << "\","
         << "\"patch_count\":" << patchCount << ","
         << details.str();

    return BuildJsonResponse(true, data.str());
}

// Handler: HIDE_DEBUG_FULL - Full anti-debug bypass (PEB + heap + more)
std::string HandleHideDebugFull(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::stringstream details;
    int totalPatches = 0;

    // First do PEB patches
    duint pebAddr = DbgValFromString("peb()");
    if (pebAddr != 0) {
        // BeingDebugged
        unsigned char zero = 0;
        if (DbgMemWrite(pebAddr + 0x2, &zero, 1)) {
            totalPatches++;
            g_antiDebugState.pebPatched = true;
        }

        // NtGlobalFlag
#ifdef _WIN64
        duint ntGlobalFlagOffset = 0xBC;
#else
        duint ntGlobalFlagOffset = 0x68;
#endif
        uint32_t ntGlobalFlag = 0;
        if (DbgMemRead(pebAddr + ntGlobalFlagOffset, &ntGlobalFlag, 4)) {
            uint32_t newFlag = ntGlobalFlag & ~0x70;
            if (DbgMemWrite(pebAddr + ntGlobalFlagOffset, &newFlag, 4)) {
                totalPatches++;
                g_antiDebugState.ntGlobalFlagPatched = true;
            }
        }

        // ProcessHeap flags (PEB+0x18 for x86, PEB+0x30 for x64 points to heap)
#ifdef _WIN64
        duint heapPtrOffset = 0x30;
        duint heapFlagsOffset = 0x70;
        duint heapForceFlagsOffset = 0x74;
#else
        duint heapPtrOffset = 0x18;
        duint heapFlagsOffset = 0x40;
        duint heapForceFlagsOffset = 0x44;
#endif

        duint heapAddr = 0;
        if (DbgMemRead(pebAddr + heapPtrOffset, &heapAddr, sizeof(heapAddr)) && heapAddr != 0) {
            // Patch Heap.Flags
            uint32_t heapFlags = 0;
            if (DbgMemRead(heapAddr + heapFlagsOffset, &heapFlags, 4)) {
                uint32_t newFlags = heapFlags & ~0x50000062;  // Clear debug flags
                newFlags |= 0x2;  // HEAP_GROWABLE
                if (DbgMemWrite(heapAddr + heapFlagsOffset, &newFlags, 4)) {
                    totalPatches++;
                    g_antiDebugState.heapFlagsPatched = true;
                }
            }

            // Patch Heap.ForceFlags
            uint32_t forceFlags = 0;
            if (DbgMemRead(heapAddr + heapForceFlagsOffset, &forceFlags, 4)) {
                if (forceFlags != 0) {
                    uint32_t newForceFlags = 0;
                    if (DbgMemWrite(heapAddr + heapForceFlagsOffset, &newForceFlags, 4)) {
                        totalPatches++;
                    }
                }
            }
        }
    }

    // Use x64dbg's built-in hide debugger command
    DbgCmdExec("HideDebugger");

    LogInfo("Full anti-debug bypass applied: %d patches", totalPatches);

    std::stringstream data;
    data << "\"message\":\"Full anti-debug bypass applied\","
         << "\"patch_count\":" << totalPatches << ","
         << "\"peb_patched\":" << (g_antiDebugState.pebPatched ? "true" : "false") << ","
         << "\"ntglobalflag_patched\":" << (g_antiDebugState.ntGlobalFlagPatched ? "true" : "false") << ","
         << "\"heap_patched\":" << (g_antiDebugState.heapFlagsPatched ? "true" : "false");

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_ANTI_DEBUG_STATUS - Get current anti-debug bypass status
std::string HandleGetAntiDebugStatus(const std::string& request) {
    std::stringstream data;
    data << "\"peb_patched\":" << (g_antiDebugState.pebPatched ? "true" : "false") << ","
         << "\"ntglobalflag_patched\":" << (g_antiDebugState.ntGlobalFlagPatched ? "true" : "false") << ","
         << "\"heap_patched\":" << (g_antiDebugState.heapFlagsPatched ? "true" : "false") << ","
         << "\"timing_hooked\":" << (g_antiDebugState.timingHooked ? "true" : "false");

    return BuildJsonResponse(true, data.str());
}

// Handler: PATCH_DBG_CHECK - Patch a specific IsDebuggerPresent call
std::string HandlePatchDbgCheck(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    std::string patchType = ExtractStringField(request, "type");

    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    std::string errorMsg;
    duint address = ResolveAddress(addressStr, errorMsg);
    if (address == 0 && !errorMsg.empty()) {
        return BuildAddressError(errorMsg, addressStr);
    }

    // Default: NOP out the call and make EAX=0
    // Typical IsDebuggerPresent call: CALL <addr>; TEST EAX,EAX; JNZ <bad>
    // We can patch the call to: XOR EAX,EAX; NOP; NOP; NOP (5 bytes for call)
    unsigned char patch[5];
    int patchSize = 5;

    if (patchType == "ret0" || patchType.empty()) {
        // XOR EAX, EAX (2 bytes) + NOP*3
        patch[0] = 0x31;  // XOR
        patch[1] = 0xC0;  // EAX, EAX
        patch[2] = 0x90;  // NOP
        patch[3] = 0x90;  // NOP
        patch[4] = 0x90;  // NOP
    } else if (patchType == "ret1") {
        // MOV EAX, 1 (5 bytes)
        patch[0] = 0xB8;  // MOV EAX
        patch[1] = 0x01;
        patch[2] = 0x00;
        patch[3] = 0x00;
        patch[4] = 0x00;
    } else if (patchType == "nop") {
        // Just NOP everything
        patch[0] = 0x90;
        patch[1] = 0x90;
        patch[2] = 0x90;
        patch[3] = 0x90;
        patch[4] = 0x90;
    } else {
        return BuildJsonResponse(false, "\"error\":\"Invalid patch type (use ret0, ret1, or nop)\"");
    }

    // Read original bytes first
    unsigned char original[5] = {0};
    DbgMemRead(address, original, 5);

    // Write the patch
    if (!DbgMemWrite(address, patch, patchSize)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to write patch\"");
    }

    LogInfo("Patched debug check at 0x%llx with %s", address, patchType.c_str());

    std::stringstream data;
    data << "\"address\":\"" << std::hex << address << std::dec << "\","
         << "\"patch_type\":\"" << patchType << "\","
         << "\"original\":\"";
    for (int i = 0; i < 5; i++) {
        data << std::hex << std::setw(2) << std::setfill('0') << (int)original[i];
    }
    data << std::dec << "\"";

    return BuildJsonResponse(true, data.str());
}

// ============================================================================
// PHASE 6: CODE COVERAGE HANDLERS
// ============================================================================

// Handler: START_COVERAGE - Start code coverage tracking
std::string HandleStartCoverage(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    InitCoverageLock();
    EnterCriticalSection(&g_coverageLock);

    // Parse options
    std::string moduleName = ExtractStringField(request, "module");
    bool clearExisting = ExtractIntField(request, "clear", 1) != 0;

    if (clearExisting) {
        g_coverageState.entries.clear();
        g_coverageState.basicBlocks.clear();
        g_coverageState.totalHits = 0;
    }

    g_coverageState.moduleName = moduleName;
    g_coverageState.startTime = GetTickCount64();
    g_coverageState.enabled = true;

    LeaveCriticalSection(&g_coverageLock);

    // Enable tracing to collect coverage
    DbgCmdExec("TraceSetLogFile \"\"");  // Disable trace file
    DbgCmdExec("TraceSetCondition 1");   // Always trace

    LogInfo("Coverage started for module: %s", moduleName.empty() ? "(all)" : moduleName.c_str());

    std::stringstream data;
    data << "\"message\":\"Coverage tracking started\","
         << "\"module\":\"" << JsonEscape(moduleName) << "\"";

    return BuildJsonResponse(true, data.str());
}

// Handler: STOP_COVERAGE - Stop code coverage tracking
std::string HandleStopCoverage(const std::string& request) {
    InitCoverageLock();
    EnterCriticalSection(&g_coverageLock);

    g_coverageState.enabled = false;
    uint64_t duration = GetTickCount64() - g_coverageState.startTime;
    size_t uniqueAddrs = g_coverageState.entries.size();
    uint64_t totalHits = g_coverageState.totalHits;

    LeaveCriticalSection(&g_coverageLock);

    LogInfo("Coverage stopped: %zu unique addresses, %llu total hits", uniqueAddrs, totalHits);

    std::stringstream data;
    data << "\"message\":\"Coverage tracking stopped\","
         << "\"unique_addresses\":" << uniqueAddrs << ","
         << "\"total_hits\":" << totalHits << ","
         << "\"duration_ms\":" << duration;

    return BuildJsonResponse(true, data.str());
}

// Handler: GET_COVERAGE_DATA - Get coverage data
std::string HandleGetCoverageData(const std::string& request) {
    InitCoverageLock();
    EnterCriticalSection(&g_coverageLock);

    int offset = ExtractIntField(request, "offset", 0);
    int limit = ExtractIntField(request, "limit", 1000);
    std::string sortBy = ExtractStringField(request, "sort");

    if (limit > 10000) limit = 10000;
    if (limit < 1) limit = 1;

    // Build list for sorting/pagination
    std::vector<std::pair<uint64_t, CoverageEntry*>> sortedEntries;
    for (auto& pair : g_coverageState.entries) {
        sortedEntries.push_back({pair.first, &pair.second});
    }

    // Sort if requested
    if (sortBy == "hits") {
        std::sort(sortedEntries.begin(), sortedEntries.end(),
            [](const auto& a, const auto& b) { return a.second->hitCount > b.second->hitCount; });
    } else if (sortBy == "address") {
        std::sort(sortedEntries.begin(), sortedEntries.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });
    }

    std::stringstream data;
    data << "\"total\":" << sortedEntries.size() << ","
         << "\"offset\":" << offset << ","
         << "\"enabled\":" << (g_coverageState.enabled ? "true" : "false") << ","
         << "\"entries\":[";

    int count = 0;
    for (size_t i = offset; i < sortedEntries.size() && count < limit; i++, count++) {
        if (count > 0) data << ",";

        CoverageEntry* entry = sortedEntries[i].second;
        data << "{\"address\":\"" << std::hex << entry->address << std::dec << "\","
             << "\"hit_count\":" << entry->hitCount << ","
             << "\"module\":\"" << JsonEscape(entry->module) << "\","
             << "\"symbol\":\"" << JsonEscape(entry->symbol) << "\"}";
    }
    data << "]";

    LeaveCriticalSection(&g_coverageLock);

    return BuildJsonResponse(true, data.str());
}

// Handler: CLEAR_COVERAGE - Clear coverage data
std::string HandleClearCoverage(const std::string& request) {
    InitCoverageLock();
    EnterCriticalSection(&g_coverageLock);

    g_coverageState.entries.clear();
    g_coverageState.basicBlocks.clear();
    g_coverageState.totalHits = 0;

    LeaveCriticalSection(&g_coverageLock);

    return BuildJsonResponse(true, "\"message\":\"Coverage data cleared\"");
}

// Handler: GET_COVERAGE_STATS - Get coverage statistics
std::string HandleGetCoverageStats(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    InitCoverageLock();
    EnterCriticalSection(&g_coverageLock);

    // Calculate stats per module
    std::map<std::string, uint64_t> moduleHits;
    std::map<std::string, uint64_t> moduleAddresses;

    for (const auto& pair : g_coverageState.entries) {
        const std::string& mod = pair.second.module;
        moduleHits[mod] += pair.second.hitCount;
        moduleAddresses[mod]++;
    }

    uint64_t totalHits = g_coverageState.totalHits;
    size_t totalAddresses = g_coverageState.entries.size();

    LeaveCriticalSection(&g_coverageLock);

    std::stringstream data;
    data << "\"enabled\":" << (g_coverageState.enabled ? "true" : "false") << ","
         << "\"total_hits\":" << totalHits << ","
         << "\"unique_addresses\":" << totalAddresses << ","
         << "\"modules\":[";

    int modCount = 0;
    for (const auto& pair : moduleAddresses) {
        if (modCount > 0) data << ",";
        data << "{\"name\":\"" << JsonEscape(pair.first) << "\","
             << "\"addresses\":" << pair.second << ","
             << "\"hits\":" << moduleHits[pair.first] << "}";
        modCount++;
    }
    data << "]";

    return BuildJsonResponse(true, data.str());
}

// Handler: EXPORT_COVERAGE - Export coverage data to file
std::string HandleExportCoverage(const std::string& request) {
    std::string filePath = ExtractStringField(request, "file");
    std::string format = ExtractStringField(request, "format");

    if (filePath.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing file path\"");
    }

    if (format.empty()) format = "csv";

    InitCoverageLock();
    EnterCriticalSection(&g_coverageLock);

    FILE* file = fopen(filePath.c_str(), "w");
    if (!file) {
        LeaveCriticalSection(&g_coverageLock);
        return BuildJsonResponse(false, "\"error\":\"Failed to open file for writing\"");
    }

    size_t entryCount = g_coverageState.entries.size();

    if (format == "csv") {
        fprintf(file, "address,hit_count,module,symbol\n");
        for (const auto& pair : g_coverageState.entries) {
            const CoverageEntry& entry = pair.second;
            fprintf(file, "0x%llx,%llu,%s,%s\n",
                entry.address, entry.hitCount,
                entry.module.c_str(), entry.symbol.c_str());
        }
    } else if (format == "json") {
        fprintf(file, "{\n  \"coverage\": [\n");
        int count = 0;
        for (const auto& pair : g_coverageState.entries) {
            const CoverageEntry& entry = pair.second;
            if (count > 0) fprintf(file, ",\n");
            fprintf(file, "    {\"address\": \"0x%llx\", \"hits\": %llu, \"module\": \"%s\", \"symbol\": \"%s\"}",
                entry.address, entry.hitCount, entry.module.c_str(), entry.symbol.c_str());
            count++;
        }
        fprintf(file, "\n  ]\n}\n");
    } else if (format == "drcov") {
        // DynamoRIO coverage format (compatible with lighthouse/bncov)
        fprintf(file, "DRCOV VERSION: 2\n");
        fprintf(file, "DRCOV FLAVOR: x64dbg_mcp\n");
        fprintf(file, "Module Table: version 2, count 1\n");
        fprintf(file, "Columns: id, base, end, entry, path\n");

        // Get main module info
        char mainModule[MAX_MODULE_SIZE] = "";
        duint mainBase = DbgValFromString("mod.main()");
        duint mainSize = 0;
        if (mainBase) {
            DbgGetModuleAt(mainBase, mainModule);
            // Get module size (simplified)
            mainSize = 0x100000;  // Default estimate
        }
        fprintf(file, " 0, 0x%llx, 0x%llx, 0x%llx, %s\n",
            mainBase, mainBase + mainSize, mainBase, mainModule);

        fprintf(file, "BB Table: %zu bbs\n", entryCount);
        for (const auto& pair : g_coverageState.entries) {
            // Format: module_id, start_offset, size (we use 1 for basic block size estimate)
            uint64_t offset = pair.first - mainBase;
            fprintf(file, "module[ 0]: 0x%llx, 1\n", offset);
        }
    } else {
        fclose(file);
        LeaveCriticalSection(&g_coverageLock);
        return BuildJsonResponse(false, "\"error\":\"Invalid format (use csv, json, or drcov)\"");
    }

    fclose(file);
    LeaveCriticalSection(&g_coverageLock);

    LogInfo("Exported %zu coverage entries to %s", entryCount, filePath.c_str());

    std::stringstream data;
    data << "\"message\":\"Coverage exported\","
         << "\"file\":\"" << JsonEscape(filePath) << "\","
         << "\"format\":\"" << format << "\","
         << "\"entries\":" << entryCount;

    return BuildJsonResponse(true, data.str());
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

// Handler: GET_EVENTS - Get pending debug events
std::string HandleGetEvents(const std::string& request) {
    int maxEvents = ExtractIntField(request, "max_events", 100);
    bool peek = ExtractIntField(request, "peek", 0) != 0;

    // Cap max_events to prevent memory issues
    if (maxEvents <= 0) maxEvents = 100;
    if (maxEvents > 1000) maxEvents = 1000;

    EventQueue& queue = EventQueue::Instance();

    std::string events;
    if (peek) {
        events = queue.PeekEvents(maxEvents);
    } else {
        events = queue.PopEvents(maxEvents);
    }

    std::stringstream data;
    data << "\"events\":" << events << ","
         << "\"queue_size\":" << queue.Size() << ","
         << "\"next_event_id\":" << queue.GetNextEventId();

    return BuildJsonResponse(true, data.str());
}

// Handler: CLEAR_EVENTS - Clear event queue
std::string HandleClearEvents(const std::string& request) {
    EventQueue::Instance().Clear();
    return BuildJsonResponse(true, "\"message\":\"Event queue cleared\"");
}

// Handler: GET_EVENT_STATUS - Get event system status
std::string HandleGetEventStatus(const std::string& request) {
    EventQueue& queue = EventQueue::Instance();

    std::stringstream data;
    data << "\"enabled\":" << (queue.IsEnabled() ? "true" : "false") << ","
         << "\"queue_size\":" << queue.Size() << ","
         << "\"next_event_id\":" << queue.GetNextEventId();

    return BuildJsonResponse(true, data.str());
}

// ============================================================================
// DEBUG EVENT CALLBACKS
// These are called by x64dbg when debug events occur
// ============================================================================

// Callback: Breakpoint hit
void OnBreakpoint(CBTYPE cbType, PLUG_CB_BREAKPOINT* info) {
    if (!info) return;

    std::stringstream details;
    details << "name=" << (info->breakpoint->name ? info->breakpoint->name : "")
            << ";type=" << info->breakpoint->type
            << ";enabled=" << info->breakpoint->enabled;

    EventQueue::Instance().PushEvent(
        DebugEventType::BREAKPOINT_HIT,
        info->breakpoint->addr,
        0,  // Thread ID not available in this callback
        "",
        details.str()
    );
}

// Callback: Exception occurred
void OnException(CBTYPE cbType, PLUG_CB_EXCEPTION* info) {
    if (!info) return;

    std::stringstream details;
    details << "code=" << std::hex << info->Exception->ExceptionRecord.ExceptionCode << std::dec
            << ";first_chance=" << info->Exception->dwFirstChance
            << ";flags=" << info->Exception->ExceptionRecord.ExceptionFlags;

    EventQueue::Instance().PushEvent(
        DebugEventType::EXCEPTION,
        reinterpret_cast<uint64_t>(info->Exception->ExceptionRecord.ExceptionAddress),
        0,
        "",
        details.str()
    );
}

// Callback: Debugger paused
void OnPausedDebug(CBTYPE cbType, PLUG_CB_PAUSEDEBUG* info) {
    // Get current address
    duint cip = DbgValFromString("cip");

    EventQueue::Instance().PushEvent(
        DebugEventType::PAUSED,
        cip,
        DbgGetThreadId(),
        "",
        ""
    );
}

// Callback: Debugger resumed
void OnResumedDebug(CBTYPE cbType, PLUG_CB_RESUMEDEBUG* info) {
    EventQueue::Instance().PushEvent(
        DebugEventType::RUNNING,
        0,
        DbgGetThreadId(),
        "",
        ""
    );
}

// Callback: Stepped (single step completed)
void OnStepped(CBTYPE cbType, PLUG_CB_STEPPED* info) {
    duint cip = DbgValFromString("cip");

    EventQueue::Instance().PushEvent(
        DebugEventType::STEPPED,
        cip,
        DbgGetThreadId(),
        "",
        ""
    );
}

// Callback: Process created (debugging started)
void OnCreateProcess(CBTYPE cbType, PLUG_CB_CREATEPROCESS* info) {
    if (!info || !info->CreateProcessInfo) return;

    std::stringstream details;
    details << "base=" << std::hex << info->CreateProcessInfo->lpBaseOfImage << std::dec;

    char modulePath[MAX_PATH] = "";
    if (info->CreateProcessInfo->lpBaseOfImage) {
        DbgGetModuleAt(reinterpret_cast<duint>(info->CreateProcessInfo->lpBaseOfImage), modulePath);
    }

    EventQueue::Instance().PushEvent(
        DebugEventType::PROCESS_STARTED,
        reinterpret_cast<uint64_t>(info->CreateProcessInfo->lpBaseOfImage),
        static_cast<uint32_t>(GetProcessId(info->CreateProcessInfo->hProcess)),
        modulePath,
        details.str()
    );
}

// Callback: Process exited
void OnExitProcess(CBTYPE cbType, PLUG_CB_EXITPROCESS* info) {
    if (!info) return;

    std::stringstream details;
    details << "exit_code=" << info->ExitProcess->dwExitCode;

    EventQueue::Instance().PushEvent(
        DebugEventType::PROCESS_EXITED,
        0,
        0,
        "",
        details.str()
    );
}

// Callback: Thread created
void OnCreateThread(CBTYPE cbType, PLUG_CB_CREATETHREAD* info) {
    if (!info || !info->CreateThread) return;

    std::stringstream details;
    details << "start_address=" << std::hex << info->CreateThread->lpStartAddress << std::dec;

    EventQueue::Instance().PushEvent(
        DebugEventType::THREAD_CREATED,
        reinterpret_cast<uint64_t>(info->CreateThread->lpStartAddress),
        info->dwThreadId,
        "",
        details.str()
    );
}

// Callback: Thread exited
void OnExitThread(CBTYPE cbType, PLUG_CB_EXITTHREAD* info) {
    if (!info) return;

    std::stringstream details;
    details << "exit_code=" << info->ExitThread->dwExitCode;

    EventQueue::Instance().PushEvent(
        DebugEventType::THREAD_EXITED,
        0,
        info->dwThreadId,
        "",
        details.str()
    );
}

// Callback: Module loaded
void OnLoadDll(CBTYPE cbType, PLUG_CB_LOADDLL* info) {
    if (!info || !info->LoadDll) return;

    char modulePath[MAX_PATH] = "";
    if (info->LoadDll->lpBaseOfDll) {
        DbgGetModuleAt(reinterpret_cast<duint>(info->LoadDll->lpBaseOfDll), modulePath);
    }

    EventQueue::Instance().PushEvent(
        DebugEventType::MODULE_LOADED,
        reinterpret_cast<uint64_t>(info->LoadDll->lpBaseOfDll),
        0,
        modulePath,
        ""
    );
}

// Callback: Module unloaded
void OnUnloadDll(CBTYPE cbType, PLUG_CB_UNLOADDLL* info) {
    if (!info || !info->UnloadDll) return;

    EventQueue::Instance().PushEvent(
        DebugEventType::MODULE_UNLOADED,
        reinterpret_cast<uint64_t>(info->UnloadDll->lpBaseOfDll),
        0,
        "",
        ""
    );
}

// Callback: System breakpoint (initial break)
void OnSystemBreakpoint(CBTYPE cbType, PLUG_CB_SYSTEMBREAKPOINT* info) {
    duint cip = DbgValFromString("cip");

    EventQueue::Instance().PushEvent(
        DebugEventType::SYSTEM_BREAKPOINT,
        cip,
        DbgGetThreadId(),
        "",
        ""
    );
}

// Handler: LOAD_BINARY - Load binary into debugger
std::string HandleLoadBinary(const std::string& request) {
    std::string path = ExtractStringField(request, "path");
    std::string args = ExtractStringField(request, "arguments");
    std::string workingDir = ExtractStringField(request, "working_directory");

    if (path.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing path\"");
    }

    // Build command
    std::string cmd = "init \"" + path + "\"";
    if (!args.empty()) {
        cmd += ", \"" + args + "\"";
    }
    if (!workingDir.empty()) {
        cmd += ", \"" + workingDir + "\"";
    }

    if (!DbgCmdExec(cmd.c_str())) {
        return BuildJsonResponse(false, "\"error\":\"Failed to load binary\"");
    }

    LogInfo("Loaded binary: %s", path.c_str());
    return BuildJsonResponse(true, "\"message\":\"Binary loaded\"");
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
                    // Core debugger state
                    case GET_STATE:
                        response = HandleGetState(request);
                        break;
                    case LOAD_BINARY:
                        response = HandleLoadBinary(request);
                        break;
                    case GET_REGISTERS:
                        response = HandleGetRegisters(request);
                        break;
                    case SET_REGISTER:
                        response = HandleSetRegister(request);
                        break;
                    case READ_MEMORY:
                        response = HandleReadMemory(request);
                        break;
                    case WRITE_MEMORY:
                        response = HandleWriteMemory(request);
                        break;

                    // Execution control
                    case RUN:
                        response = HandleRun(request);
                        break;
                    case PAUSE:
                        response = HandlePause(request);
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

                    // Analysis
                    case GET_STACK:
                        response = HandleGetStack(request);
                        break;
                    case GET_MODULES:
                        response = HandleGetModules(request);
                        break;
                    case GET_THREADS:
                        response = HandleGetThreads(request);
                        break;
                    case DISASSEMBLE:
                        response = HandleDisassemble(request);
                        break;
                    case GET_INSTRUCTION:
                        response = HandleGetInstruction(request);
                        break;
                    case EVALUATE_EXPRESSION:
                        response = HandleEvaluateExpression(request);
                        break;

                    // Breakpoints
                    case SET_BREAKPOINT:
                        response = HandleSetBreakpoint(request);
                        break;
                    case DELETE_BREAKPOINT:
                        response = HandleDeleteBreakpoint(request);
                        break;
                    case LIST_BREAKPOINTS:
                        response = HandleListBreakpoints(request);
                        break;
                    case SET_HARDWARE_BREAKPOINT:
                        response = HandleSetHardwareBreakpoint(request);
                        break;
                    case SET_MEMORY_BREAKPOINT:
                        response = HandleSetMemoryBreakpoint(request);
                        break;
                    case DELETE_MEMORY_BREAKPOINT:
                        response = HandleDeleteMemoryBreakpoint(request);
                        break;

                    // Memory tools
                    case GET_MEMORY_MAP:
                        response = HandleGetMemoryMap(request);
                        break;
                    case GET_MEMORY_INFO:
                        response = HandleGetMemoryInfo(request);
                        break;

                    // Module tools
                    case GET_MODULE_IMPORTS:
                        response = HandleGetModuleImports(request);
                        break;
                    case GET_MODULE_EXPORTS:
                        response = HandleGetModuleExports(request);
                        break;

                    // Comments
                    case SET_COMMENT:
                        response = HandleSetComment(request);
                        break;
                    case GET_COMMENT:
                        response = HandleGetComment(request);
                        break;

                    // Advanced control
                    case SKIP_INSTRUCTION:
                        response = HandleSkipInstruction(request);
                        break;
                    case RUN_UNTIL_RETURN:
                        response = HandleRunUntilReturn(request);
                        break;
                    case HIDE_DEBUGGER:
                        response = HandleHideDebugger(request);
                        break;

                    // Wait/Synchronization (Phase 1)
                    case WAIT_PAUSED:
                        response = HandleWaitPaused(request);
                        break;
                    case WAIT_RUNNING:
                        response = HandleWaitRunning(request);
                        break;
                    case WAIT_DEBUGGING:
                        response = HandleWaitDebugging(request);
                        break;

                    // Symbol resolution
                    case RESOLVE_SYMBOL:
                        response = HandleResolveSymbol(request);
                        break;

                    // Health check
                    case PING:
                        response = BuildJsonResponse(true, "\"message\":\"pong\"");
                        break;

                    // Events
                    case GET_EVENTS:
                        response = HandleGetEvents(request);
                        break;
                    case CLEAR_EVENTS:
                        response = HandleClearEvents(request);
                        break;
                    case GET_EVENT_STATUS:
                        response = HandleGetEventStatus(request);
                        break;

                    // Memory allocation (Phase 3)
                    case VIRT_ALLOC:
                        response = HandleVirtAlloc(request);
                        break;
                    case VIRT_FREE:
                        response = HandleVirtFree(request);
                        break;
                    case VIRT_PROTECT:
                        response = HandleVirtProtect(request);
                        break;
                    case MEM_SET:
                        response = HandleMemSet(request);
                        break;
                    case CHECK_VALID_PTR:
                        response = HandleCheckValidPtr(request);
                        break;

                    // Enhanced breakpoints (Phase 3)
                    case TOGGLE_BREAKPOINT:
                        response = HandleToggleBreakpoint(request);
                        break;
                    case DELETE_HARDWARE_BREAKPOINT:
                        response = HandleDeleteHardwareBreakpoint(request);
                        break;
                    case TOGGLE_HARDWARE_BREAKPOINT:
                        response = HandleToggleHardwareBreakpoint(request);
                        break;
                    case TOGGLE_MEMORY_BREAKPOINT:
                        response = HandleToggleMemoryBreakpoint(request);
                        break;
                    case LIST_ALL_BREAKPOINTS:
                        response = HandleListAllBreakpoints(request);
                        break;

                    // Phase 4: Tracing
                    case START_TRACE:
                        response = HandleStartTrace(request);
                        break;
                    case STOP_TRACE:
                        response = HandleStopTrace(request);
                        break;
                    case GET_TRACE_DATA:
                        response = HandleGetTraceData(request);
                        break;
                    case CLEAR_TRACE:
                        response = HandleClearTrace(request);
                        break;
                    case SET_API_BREAKPOINT:
                        response = HandleSetApiBreakpoint(request);
                        break;
                    case GET_API_LOG:
                        response = HandleGetApiLog(request);
                        break;
                    case CLEAR_API_LOG:
                        response = HandleClearApiLog(request);
                        break;

                    // Phase 4: String & Pattern Search
                    case FIND_STRINGS:
                        response = HandleFindStrings(request);
                        break;
                    case PATTERN_SCAN:
                        response = HandlePatternScan(request);
                        break;
                    case XOR_DECRYPT:
                        response = HandleXorDecrypt(request);
                        break;

                    // Phase 4: References & Analysis
                    case FIND_REFERENCES:
                        response = HandleFindReferences(request);
                        break;
                    case GET_CALL_STACK_DETAILED:
                        response = HandleGetCallStackDetailed(request);
                        break;

                    // Phase 5: Anti-Debug Bypass
                    case HIDE_DEBUG_PEB:
                        response = HandleHideDebugPeb(request);
                        break;
                    case HIDE_DEBUG_FULL:
                        response = HandleHideDebugFull(request);
                        break;
                    case GET_ANTI_DEBUG_STATUS:
                        response = HandleGetAntiDebugStatus(request);
                        break;
                    case PATCH_DBG_CHECK:
                        response = HandlePatchDbgCheck(request);
                        break;

                    // Phase 6: Code Coverage
                    case START_COVERAGE:
                        response = HandleStartCoverage(request);
                        break;
                    case STOP_COVERAGE:
                        response = HandleStopCoverage(request);
                        break;
                    case GET_COVERAGE_DATA:
                        response = HandleGetCoverageData(request);
                        break;
                    case CLEAR_COVERAGE:
                        response = HandleClearCoverage(request);
                        break;
                    case GET_COVERAGE_STATS:
                        response = HandleGetCoverageStats(request);
                        break;
                    case EXPORT_COVERAGE:
                        response = HandleExportCoverage(request);
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

    // Register debug event callbacks for event system
    _plugin_registercallback(g_pluginHandle, CB_BREAKPOINT, (CBPLUGIN)OnBreakpoint);
    _plugin_registercallback(g_pluginHandle, CB_EXCEPTION, (CBPLUGIN)OnException);
    _plugin_registercallback(g_pluginHandle, CB_PAUSEDEBUG, (CBPLUGIN)OnPausedDebug);
    _plugin_registercallback(g_pluginHandle, CB_RESUMEDEBUG, (CBPLUGIN)OnResumedDebug);
    _plugin_registercallback(g_pluginHandle, CB_STEPPED, (CBPLUGIN)OnStepped);
    _plugin_registercallback(g_pluginHandle, CB_CREATEPROCESS, (CBPLUGIN)OnCreateProcess);
    _plugin_registercallback(g_pluginHandle, CB_EXITPROCESS, (CBPLUGIN)OnExitProcess);
    _plugin_registercallback(g_pluginHandle, CB_CREATETHREAD, (CBPLUGIN)OnCreateThread);
    _plugin_registercallback(g_pluginHandle, CB_EXITTHREAD, (CBPLUGIN)OnExitThread);
    _plugin_registercallback(g_pluginHandle, CB_LOADDLL, (CBPLUGIN)OnLoadDll);
    _plugin_registercallback(g_pluginHandle, CB_UNLOADDLL, (CBPLUGIN)OnUnloadDll);
    _plugin_registercallback(g_pluginHandle, CB_SYSTEMBREAKPOINT, (CBPLUGIN)OnSystemBreakpoint);

    LogInfo("Registered 12 debug event callbacks");

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
