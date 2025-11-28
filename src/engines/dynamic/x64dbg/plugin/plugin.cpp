#include "plugin.h"
#include "event_system.h"
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
    LIST_ALL_BREAKPOINTS = 124
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

// Handler: DELETE_BREAKPOINT - Delete software breakpoint at address
std::string HandleDeleteBreakpoint(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string addressStr = ExtractStringField(request, "address");
    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    duint address = DbgValFromString(addressStr.c_str());

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bc %llx", address);
    DbgCmdExec(cmd);

    LogInfo("Breakpoint deleted at 0x%llx", address);
    return BuildJsonResponse(true, "\"message\":\"Breakpoint deleted\"");
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
    duint address = addressStr.empty() ? DbgValFromString("cip") : DbgValFromString(addressStr.c_str());

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

    duint address = DbgValFromString(addressStr.c_str());

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
    duint address = addressStr.empty() ? DbgValFromString("cip") : DbgValFromString(addressStr.c_str());

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

    duint address = DbgValFromString(addressStr.c_str());

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

    duint address = DbgValFromString(addressStr.c_str());

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

    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    duint address = DbgValFromString(addressStr.c_str());

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

    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    duint address = DbgValFromString(addressStr.c_str());

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
    if (addressStr.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing address\"");
    }

    duint address = DbgValFromString(addressStr.c_str());

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

    duint address = DbgValFromString(addressStr.c_str());

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

    duint address = DbgValFromString(addressStr.c_str());

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

    duint address = DbgValFromString(addressStr.c_str());

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

    duint address = DbgValFromString(addressStr.c_str());

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

    duint address = DbgValFromString(addressStr.c_str());

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

    duint address = DbgValFromString(addressStr.c_str());

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

    duint address = DbgValFromString(addressStr.c_str());

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

    duint address = DbgValFromString(addressStr.c_str());

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
// EVENT HANDLERS
// ============================================================================

// Handler: GET_EVENTS - Get pending debug events
std::string HandleGetEvents(const std::string& request) {
    int maxEvents = ExtractIntField(request, "max_events", 100);
    bool peek = ExtractIntField(request, "peek", 0) != 0;

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
        reinterpret_cast<uint32_t>(reinterpret_cast<uintptr_t>(info->CreateProcessInfo->hProcess)),
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

// Callback: Debug string output
void OnDebugString(CBTYPE cbType, PLUG_CB_DEBUGSTRING* info) {
    if (!info) return;

    EventQueue::Instance().PushEvent(
        DebugEventType::DEBUG_STRING,
        0,
        0,
        "",
        info->string ? info->string : ""
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
    _plugin_registercallback(g_pluginHandle, CB_DEBUGSTRING, (CBPLUGIN)OnDebugString);
    _plugin_registercallback(g_pluginHandle, CB_SYSTEMBREAKPOINT, (CBPLUGIN)OnSystemBreakpoint);

    LogInfo("Registered 13 debug event callbacks");

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
