#include "plugin.h"
#include "event_system.h"
#include "../pipe_protocol.h"
#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>
#include <exception>
#include <sstream>
#include <iomanip>
#include <set>
#include <map>
#include <algorithm>
#include <cctype>
#include <atomic>      // g_running / g_serverProcessId cross thread boundaries
#include <cstring>
#include <cstdlib>
#include <wincrypt.h>  // For CryptGenRandom
#include <sddl.h>      // For ConvertSidToStringSid / SDDL security descriptors

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
    EXECUTE_COMMAND = 16,

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
static HANDLE g_pipeReadyEvent = nullptr;  // Event signaled when pipe is created

// g_running is written by pluginSetup/pluginStop (x64dbg's thread) and read by
// PipeServerThread and by the wait handlers running on it. A plain `bool` gives
// the compiler licence to hoist the load out of `while (g_running)`, so a
// shutdown could be missed entirely and the loop would spin inside a DLL that
// is about to be unloaded (see the F-20 comment on pluginStop). std::atomic
// with the default seq_cst ordering costs nothing measurable at these poll
// rates and makes the shutdown handshake actually observable.
static std::atomic<bool> g_running{false};

// PID of the obsidian_server.exe we spawned, recorded by SpawnHTTPServer and
// read by PipeServerThread to authenticate the pipe peer (finding F-17). Zero
// means "no server spawned yet", which must be treated as "reject everything".
static std::atomic<DWORD> g_serverProcessId{0};

// Serialises access to g_pipeServer between PipeServerThread (which owns and
// is the ONLY closer of the handle) and pluginStop (which may only cancel I/O
// on it). See the F-20 / handle-recycling comment on pluginStop.
//
// Initialised once from pluginInit(), which x64dbg calls on a single thread
// before anything else in this plugin runs -- deliberately NOT lazily, because
// a lazy "if (!initialised) InitializeCriticalSection(...)" is itself the race
// it is trying to protect against.
static CRITICAL_SECTION g_pipeHandleLock;
static bool g_pipeHandleLockInit = false;

// PHASE 4: TRACING & API LOGGING DATA STRUCTURES

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

// PHASE 5: ANTI-DEBUG BYPASS STATE

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

// PHASE 6: CODE COVERAGE DATA STRUCTURES

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
// ---------------------------------------------------------------------------
// Format-string checking for the log wrappers (CWE-686 / MSVC C4477)
//
// These are variadic wrappers around vsnprintf, and MSVC applies its C4477
// format/argument check only to the printf family it recognises. It therefore
// could not see ANY call site here -- which is exactly how twenty
// `%llx`-with-`duint` bugs survived: the identical mistake in a direct
// snprintf() was flagged on the very first x86 build, while the same mistake
// inside LogInfo() was silent.
//
// `duint` is 64-bit on x64 and 32-bit on x86, so `%llx` on the 32-bit build
// read eight bytes where four were pushed: a garbage high dword AND every
// following argument shifted. In a call like
// LogInfo("... 0x%llx (type: %s)", address, str) that shift hands `%s` a
// non-pointer -- a crash, not merely wrong output.
//
// _Printf_format_string_ is what MSVC offers here. Be precise about its reach:
// it drives /analyze (and IntelliSense), NOT the ordinary compile, so it is a
// documentation and static-analysis aid rather than a build-time gate. The
// arguments are cast at the call sites for that reason -- the annotation alone
// would not have caught these.
//
// SAL arrives via <sal.h>, which every MSVC CRT header pulls in through
// <vcruntime.h> (so <cstdio> above is sufficient). The fallback below means a
// toolchain without SAL still compiles: an annotation that documents intent
// must never be the thing that breaks a build.
// ---------------------------------------------------------------------------
#ifndef _Printf_format_string_
#define _Printf_format_string_
#endif

void LogInfo(_Printf_format_string_ const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    _plugin_logprintf("[MCP] %s\n", buffer);
}

void LogError(_Printf_format_string_ const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    _plugin_logprintf("[MCP ERROR] %s\n", buffer);
}

// JSON HELPER FUNCTIONS (Simple parser - no external dependencies)

// Escape string for JSON output (handles backslashes, quotes, newlines, etc.)
//
// AUDIT (JSON escaping / non-ASCII): every byte outside 0x20..0x7E is emitted
// as a \u escape, not just the C0 controls.
//
// WHY: the strings that reach here are not the plugin's own -- they are module
// paths, symbol names, debug strings and disassembly text lifted out of the
// process under analysis, i.e. attacker-chosen bytes. x64dbg hands them over as
// raw `char` with no declared encoding, so an 0x80..0xFF byte passed through
// verbatim produces a JSON document that is not valid UTF-8. The Python side
// calls response.json(); invalid UTF-8 raises there, so a single crafted module
// name turns every subsequent response on that endpoint into an opaque decode
// error -- a denial of service on the analysis session that the sample controls
// for free. 0x7F (DEL) is escaped for the same reason.
//
// Escaping as \u00XX means a high byte round-trips as the U+0080..U+00FF code
// point of the same value (a latin-1 reading of the byte). That is a lossy
// guess about the encoding, but it is a REVERSIBLE and always-decodable one:
// the consumer still sees the byte value, and the transport never breaks.
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
            default: {
                unsigned char uc = static_cast<unsigned char>(c);
                // Anything outside printable ASCII: control characters AND
                // every byte >= 0x7F. See the comment above for why the high
                // half cannot be passed through.
                if (uc < 0x20 || uc >= 0x7F) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", uc);
                    result += buf;
                } else {
                    result += c;
                }
                break;
            }
        }
    }
    return result;
}

// Extract integer value from JSON string
//
// AUDIT (silent parse failure): this used to discard sscanf's return value, so
// an unparseable value ("timeout":"abc", "timeout":null, a truncated request)
// left `value` at its initialiser 0 and the function returned 0 instead of the
// caller's defaultValue. That is not a cosmetic difference: every caller picked
// its default deliberately, and 0 is frequently the WORST possible value for
// the field -- `ExtractIntField(request, "type", -1)` would report request type
// 0 rather than "absent", and the wait handlers would collapse their timeout.
// Honour the conversion result and fall back to defaultValue on failure.
int ExtractIntField(const std::string& json, const char* fieldName, int defaultValue = 0) {
    std::string searchStr = std::string("\"") + fieldName + "\":";
    size_t pos = json.find(searchStr);
    if (pos == std::string::npos) return defaultValue;

    pos += searchStr.length();
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    if (pos >= json.length()) return defaultValue;

    // JSON booleans reach integer fields all the time here, because several
    // request fields are conceptually flags (trace_into, peek) and the Python
    // side is free to send real booleans. Map them explicitly rather than
    // letting them fail parsing and silently take the default -- "false" taking
    // a default of 1 would invert the caller's intent.
    if (json.compare(pos, 4, "true") == 0) return 1;
    if (json.compare(pos, 5, "false") == 0) return 0;

    int value = 0;
    if (sscanf(json.c_str() + pos, "%d", &value) != 1) {
        return defaultValue;
    }
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

// ---------------------------------------------------------------------------
// OUTPUT PATH CONFINEMENT -- finding F-27
//
// Two handlers used to take a filesystem path straight out of the request and
// hand it to fopen(): EXPORT_COVERAGE ("file") and START_TRACE ("log_file").
// There was no canonicalisation, no confinement and no extension check, which
// made both of them an arbitrary file CREATE/OVERWRITE primitive running with
// x64dbg's privileges:
//
//   "file": "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\
//            Programs\\Startup\\x.cmd"   -> persistence
//   "file": "\\\\attacker\\share\\loot.csv" -> a UNC target makes the WRITE an
//            outbound network transfer, so the same bug is also an exfiltration
//            channel, and it is the coverage data (i.e. what the sample did)
//            that gets exfiltrated.
//
// Combined with F-17 (the pipe had no peer authentication) the process being
// debugged could reach these handlers itself, so this was not merely "the
// operator can overwrite their own files".
//
// The fix is confinement, not sanitisation: resolve the requested name against
// one fixed output directory, canonicalise the result with GetFullPathNameA,
// and then require the canonical result to still live under that directory.
// Prefix-matching AFTER canonicalisation handles every LEXICAL trick ("..",
// "....\\\\", a short 8.3 name, a trailing dot, a device name like CON which
// GetFullPathNameA rewrites to \\.\CON), because anything that spells its way
// out of the base no longer has the base as its prefix.
//
// It does NOT handle reparse points, and an earlier revision of this comment
// wrongly claimed it handled everything. GetFullPathNameA is purely lexical --
// it never touches the filesystem -- so a junction planted inside the output
// root keeps the prefix intact while sending the write somewhere else entirely.
// Since the root lives under %TEMP%, the debuggee can plant one. That is why
// IsReparsePoint is applied to the root in GetOutputRoot and to every component
// below it here. Three layers, none of them sufficient alone: the syntactic
// rejections are a fast first pass, the prefix check is the lexical control,
// and the reparse-point walk is the physical one.
// ---------------------------------------------------------------------------

// True if `path` exists AND is a reparse point (junction, directory symlink,
// mount point). CWE-59.
//
// GetFullPathNameA, which the confinement below relies on, is a purely LEXICAL
// function -- it never touches the filesystem and therefore never resolves a
// reparse point. So a prefix comparison against a canonicalised string proves
// only that the path SPELLS its way inside the root, not that it physically
// lands there. Anything that can create a directory inside the root can
// therefore redirect writes out of it, and the root lives under %TEMP%, which
// is writable by every process running as this user -- the debuggee included.
//
// A path that does not exist yet is not a reparse point and is not a problem:
// it will be created inside the root by the writer.
//
// GetFileAttributesA is kernel32, so this adds no new link dependency.
static bool IsReparsePoint(const std::string& path) {
    std::string probe = path;
    // GetFileAttributes dislikes a trailing separator on some paths. Keep the
    // one in "C:\" -- a bare drive root must stay "C:\".
    while (probe.size() > 3 && probe.back() == '\\') {
        probe.pop_back();
    }
    DWORD attrs = GetFileAttributesA(probe.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return false;  // absent: nothing to follow
    }
    return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

// Returns the single directory that plugin-written files may live in, with a
// trailing backslash. Created on demand.
static bool GetOutputRoot(std::string& outRoot) {
    outRoot.clear();

    char tempPath[MAX_PATH];
    DWORD n = GetTempPathA(MAX_PATH, tempPath);
    if (n == 0 || n >= MAX_PATH) {
        return false;
    }

    // CreateDirectoryA fails with ERROR_ALREADY_EXISTS when the name is taken,
    // and that is normally fine -- but it is ALSO what happens when the name
    // was pre-created as a junction. Ignoring the error unconditionally is what
    // let a sample point the whole output tree somewhere else and have every
    // later write follow it, with the lexical prefix check none the wiser. So
    // each level is checked after creation and the whole root is refused if
    // either is a reparse point.
    std::string base = std::string(tempPath) + "obsidian_x64dbg\\";
    CreateDirectoryA(base.c_str(), nullptr);  // ERROR_ALREADY_EXISTS is fine
    if (IsReparsePoint(base)) {
        return false;
    }

    std::string root = base + "output\\";
    CreateDirectoryA(root.c_str(), nullptr);
    if (IsReparsePoint(root)) {
        return false;
    }

    // %TEMP% itself may be an 8.3 short path or contain a symlink component, so
    // canonicalise the base too -- otherwise the prefix comparison below would
    // be against a spelling the resolved child never matches.
    char full[MAX_PATH];
    DWORD len = GetFullPathNameA(root.c_str(), MAX_PATH, full, nullptr);
    if (len == 0 || len >= MAX_PATH) {
        return false;
    }

    outRoot = full;
    if (outRoot.empty() || outRoot.back() != '\\') {
        outRoot += '\\';
    }
    return true;
}

// Case-insensitive extension whitelist. `allowed` is a nullptr-terminated array
// of lowercase extensions including the dot, e.g. {".csv", ".json", nullptr}.
static bool HasAllowedExtension(const std::string& path, const char* const* allowed) {
    size_t dot = path.find_last_of('.');
    size_t sep = path.find_last_of('\\');
    if (dot == std::string::npos) return false;
    if (sep != std::string::npos && dot < sep) return false;  // dot is in a directory name

    std::string ext = path.substr(dot);
    for (size_t i = 0; i < ext.size(); i++) {
        ext[i] = (char)tolower((unsigned char)ext[i]);
    }
    for (int i = 0; allowed[i] != nullptr; i++) {
        if (ext == allowed[i]) return true;
    }
    return false;
}

// Resolve `requested` to an absolute path inside the output root, or fail.
// On failure outError holds an already-JSON-safe explanation.
static bool ResolveConfinedOutputPath(const std::string& requested,
                                      const char* const* allowedExtensions,
                                      std::string& outPath,
                                      std::string& outError) {
    outPath.clear();
    outError.clear();

    if (requested.empty()) {
        outError = "Missing file path";
        return false;
    }
    if (requested.size() >= MAX_PATH) {
        outError = "File path too long";
        return false;
    }

    // Control characters, wildcards and the NTFS stream separator never belong
    // in a name we are about to create, and ':' additionally covers both drive
    // letters ("C:\\...") and alternate data streams ("out.csv:hidden").
    for (size_t i = 0; i < requested.size(); i++) {
        unsigned char c = (unsigned char)requested[i];
        // ':' is by far the most likely rejection in practice -- every real
        // Windows path a caller types has a drive letter -- so it gets its own
        // message. "File path contains an illegal character" told the analyst
        // nothing about what to do instead, which made a deliberate
        // confinement rule look like a malfunction.
        if (c == ':') {
            outError = "Drive letters and alternate data streams are not "
                       "permitted; give a name relative to the plugin output "
                       "directory, e.g. \"trace.csv\"";
            return false;
        }
        if (c < 0x20 || c == 0x7F || c == '"' ||
            c == '<' || c == '>' || c == '|' || c == '*' || c == '?') {
            outError = "File path contains an illegal character";
            return false;
        }
    }

    // Normalise separators so the checks below only have to reason about '\\'.
    std::string rel = requested;
    for (size_t i = 0; i < rel.size(); i++) {
        if (rel[i] == '/') rel[i] = '\\';
    }

    // A leading separator is either root-relative ("\\dir\\x") or UNC
    // ("\\\\host\\share\\x"); both leave the output root.
    if (rel[0] == '\\') {
        outError = "Absolute and UNC paths are not permitted; give a name relative to the output directory";
        return false;
    }

    // Reject ".." as a whole path component. Checking components rather than
    // searching for the substring avoids rejecting a legitimate "v1..2.csv"
    // while still catching "..\\..\\x" and "a\\..\\..\\x".
    size_t start = 0;
    while (start <= rel.size()) {
        size_t end = rel.find('\\', start);
        std::string component = (end == std::string::npos)
                                    ? rel.substr(start)
                                    : rel.substr(start, end - start);
        if (component == "..") {
            outError = "Parent-directory references are not permitted in the file path";
            return false;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }

    std::string root;
    if (!GetOutputRoot(root)) {
        outError = "Could not prepare the plugin output directory";
        return false;
    }

    std::string joined = root + rel;
    if (joined.size() >= MAX_PATH) {
        outError = "File path too long";
        return false;
    }

    char full[MAX_PATH];
    DWORD len = GetFullPathNameA(joined.c_str(), MAX_PATH, full, nullptr);
    if (len == 0 || len >= MAX_PATH) {
        outError = "File path could not be resolved";
        return false;
    }
    std::string canonical(full);

    // THE control: whatever the input did, the canonical result must still sit
    // under the output root. Windows paths are case-insensitive, so compare
    // that way -- a case-sensitive compare here would be a bypass, not a
    // hardening.
    if (canonical.size() <= root.size() ||
        _strnicmp(canonical.c_str(), root.c_str(), root.size()) != 0) {
        outError = "File path escapes the plugin output directory";
        return false;
    }

    // The prefix check above is LEXICAL, so it proves spelling, not location.
    // Walk every component strictly below the root and refuse if any of them is
    // an existing reparse point -- otherwise "sub\\trace.log", where "sub" was
    // pre-created as a junction, spells its way inside the root and writes
    // outside it. The final component is included on purpose: an existing
    // symlinked FILE is followed by fopen(..., "w") just as happily.
    //
    // This is the same control src/utils/security.py::_reject_symlinked_components
    // applies on the Python side; the C++ writer had no equivalent.
    {
        size_t pos = root.size();
        while (true) {
            size_t sep = canonical.find('\\', pos);
            std::string component = (sep == std::string::npos)
                                        ? canonical
                                        : canonical.substr(0, sep);
            if (IsReparsePoint(component)) {
                outError = "File path passes through a junction or symlink, "
                           "which could redirect the write outside the plugin "
                           "output directory";
                return false;
            }
            if (sep == std::string::npos) {
                break;
            }
            pos = sep + 1;
        }
    }

    // Extension whitelist last, on the CANONICAL path, so it cannot be dodged
    // by anything GetFullPathNameA strips (trailing dots and spaces).
    if (!HasAllowedExtension(canonical, allowedExtensions)) {
        outError = "File extension is not permitted for this output";
        return false;
    }

    outPath = canonical;
    return true;
}

// Extensions each writer may produce. Executable/script extensions are absent
// on purpose: a confined directory still should not become a drop point for
// something another process might later run.
static const char* const COVERAGE_OUTPUT_EXTENSIONS[] = {
    ".csv", ".json", ".drcov", ".txt", ".log", nullptr
};
static const char* const TRACE_LOG_EXTENSIONS[] = {
    ".txt", ".log", ".csv", nullptr
};

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

// REQUEST HANDLERS

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
    snprintf(cmd, sizeof(cmd), "bp %llx", (unsigned long long)address);

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

    LogInfo("Breakpoint set at 0x%llx", (unsigned long long)address);

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
    snprintf(cmd, sizeof(cmd), "bc %llx", (unsigned long long)address);
    DbgCmdExec(cmd);

    LogInfo("Breakpoint deleted at 0x%llx", (unsigned long long)address);

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

    LogInfo("GetStack: RSP=0x%llx, RBP=0x%llx, RIP=0x%llx, count=%d", (unsigned long long)rsp, (unsigned long long)rbp, (unsigned long long)rip, count);

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
            LogInfo("GetStack: Failed to read at 0x%llx", (unsigned long long)stackAddr);
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

    LogInfo("Wrote %zu bytes to 0x%llx", bytes.size(), (unsigned long long)address);

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
    snprintf(cmd, sizeof(cmd), "rip=%llx", (unsigned long long)newCip);
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
    snprintf(cmd, sizeof(cmd), "bph %llx, %s, %d", (unsigned long long)address, hwType.c_str(), size);
    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to set hardware breakpoint\"");
    }

    LogInfo("Hardware breakpoint set at 0x%llx (type: %s, size: %d)", (unsigned long long)address, hwType.c_str(), size);

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
    snprintf(cmd, sizeof(cmd), "bpm %llx, %s", (unsigned long long)address, memType.c_str());
    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to set memory breakpoint\"");
    }

    LogInfo("Memory breakpoint set at 0x%llx (type: %s)", (unsigned long long)address, memType.c_str());

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
    snprintf(cmd, sizeof(cmd), "bpmc %llx", (unsigned long long)address);
    DbgCmdExec(cmd);

    LogInfo("Memory breakpoint deleted at 0x%llx", (unsigned long long)address);
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

// WAIT/SYNCHRONIZATION HANDLERS (Phase 1)
//
// ---------------------------------------------------------------------------
// Finding F-20 -- plugin-image use-after-free on unload.
//
// These three handlers run on PipeServerThread and poll for up to five minutes
// on a caller-supplied timeout. They used to poll with a bare Sleep(50) and
// consult nothing but the debugger state, so once one was entered NOTHING could
// get it out early. Meanwhile pluginStop() waited 1000 ms for the pipe thread
// and then returned regardless, at which point x64dbg FreeLibrary()s this DLL --
// while a thread is still executing inside its .text and touching its globals.
// That is a use-after-free of the entire plugin image: the next instruction the
// thread retires is whatever the loader has since mapped there. A request as
// ordinary as {"type":91,"timeout":300000} sent just before x64dbg exits was
// enough to arm it.
//
// The fix is a shutdown handshake with two halves, and BOTH are required:
//   1. here -- the poll sleep becomes WaitForSingleObject(g_shutdownEvent, ...)
//      so pluginStop can pull these loops out immediately, and the loop
//      condition also checks g_running; and
//   2. in pluginStop -- it now waits long enough for that to actually happen,
//      and if the thread still has not exited it PINS the module rather than
//      letting the unload proceed. See the comment there.
//
// AbortableSleep returns true if it slept the full interval, false if shutdown
// was signalled (or the event is unusable, which is also a reason to stop).
// ---------------------------------------------------------------------------
static bool AbortableSleep(DWORD milliseconds) {
    if (!g_running.load()) {
        return false;
    }
    HANDLE shutdown = g_shutdownEvent;
    if (!shutdown) {
        // No event to wait on: fall back to a plain sleep so behaviour is
        // unchanged, but still honour g_running on the next loop iteration.
        Sleep(milliseconds);
        return g_running.load();
    }
    DWORD waitResult = WaitForSingleObject(shutdown, milliseconds);
    // WAIT_TIMEOUT is the ONLY result that means "keep waiting". WAIT_OBJECT_0
    // is shutdown; WAIT_FAILED/WAIT_ABANDONED mean the handle can no longer be
    // trusted, and continuing to spin on a broken handle inside a DLL that is
    // being torn down is exactly the failure mode F-20 describes.
    return waitResult == WAIT_TIMEOUT && g_running.load();
}

// Shared body for the F-20 early-exit reply, so all three handlers report the
// abort identically instead of pretending the wait simply timed out.
static std::string BuildWaitAbortedResponse(long long elapsedMs) {
    std::stringstream data;
    data << "\"error\":\"Wait aborted: plugin is shutting down\","
         << "\"aborted\":true,"
         << "\"elapsed_ms\":" << elapsedMs;
    return BuildJsonResponse(false, data.str());
}

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

        // F-20: abortable poll. Returning here is what lets pluginStop finish
        // before x64dbg unloads the DLL this code lives in.
        if (!AbortableSleep((DWORD)pollInterval)) {
            return BuildWaitAbortedResponse(elapsed);
        }
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

        // F-20: abortable poll -- see AbortableSleep.
        if (!AbortableSleep((DWORD)pollInterval)) {
            return BuildWaitAbortedResponse(elapsed);
        }
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

        // F-20: abortable poll -- see AbortableSleep.
        if (!AbortableSleep((DWORD)pollInterval)) {
            return BuildWaitAbortedResponse(elapsed);
        }
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
    // JsonEscape: `module` is echoed straight back from the request, so an
    // unescaped quote or backslash in it produced a malformed response body --
    // every other field in this file is escaped and these two were missed.
    std::stringstream data;
    data << "\"module\":\"" << JsonEscape(moduleName) << "\","
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
    // JsonEscape for the same reason as HandleGetModuleImports above.
    std::stringstream data;
    data << "\"module\":\"" << JsonEscape(moduleName) << "\","
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

// MEMORY ALLOCATION HANDLERS (Phase 3)

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
        snprintf(cmd, sizeof(cmd), "alloc %d, %llx", size, (unsigned long long)preferredAddr);
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

    LogInfo("Allocated %d bytes at 0x%llx", size, (unsigned long long)allocatedAddr);

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
    snprintf(cmd, sizeof(cmd), "free %llx", (unsigned long long)address);

    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to free memory\"");
    }

    LogInfo("Freed memory at 0x%llx", (unsigned long long)address);
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
    snprintf(cmd, sizeof(cmd), "setpagerights %llx, %d, %x", (unsigned long long)address, size, protection);

    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to change memory protection\"");
    }

    LogInfo("Changed protection at 0x%llx to 0x%x", (unsigned long long)address, protection);

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

    LogInfo("Filled %d bytes at 0x%llx with 0x%02x", size, (unsigned long long)address, value & 0xFF);

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

// ENHANCED BREAKPOINT HANDLERS (Phase 3)

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
        snprintf(cmd, sizeof(cmd), "bpe %llx", (unsigned long long)address);
    } else {
        snprintf(cmd, sizeof(cmd), "bpd %llx", (unsigned long long)address);
    }

    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to toggle breakpoint\"");
    }

    LogInfo("Breakpoint at 0x%llx %s", (unsigned long long)address, enable ? "enabled" : "disabled");

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
    snprintf(cmd, sizeof(cmd), "bphc %llx", (unsigned long long)address);
    DbgCmdExec(cmd);

    LogInfo("Hardware breakpoint deleted at 0x%llx", (unsigned long long)address);
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
        snprintf(cmd, sizeof(cmd), "bphe %llx", (unsigned long long)address);
    } else {
        snprintf(cmd, sizeof(cmd), "bphd %llx", (unsigned long long)address);
    }

    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to toggle hardware breakpoint\"");
    }

    LogInfo("Hardware breakpoint at 0x%llx %s", (unsigned long long)address, enable ? "enabled" : "disabled");

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
        snprintf(cmd, sizeof(cmd), "bpme %llx", (unsigned long long)address);
    } else {
        snprintf(cmd, sizeof(cmd), "bpmd %llx", (unsigned long long)address);
    }

    if (!DbgCmdExec(cmd)) {
        return BuildJsonResponse(false, "\"error\":\"Failed to toggle memory breakpoint\"");
    }

    LogInfo("Memory breakpoint at 0x%llx %s", (unsigned long long)address, enable ? "enabled" : "disabled");

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

// PHASE 4: TRACING HANDLERS

// Handler: START_TRACE - Start instruction tracing
std::string HandleStartTrace(const std::string& request) {
    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging\"");
    }

    std::string logFile = ExtractStringField(request, "log_file");

    // F-27: resolve the caller-supplied log path BEFORE touching any state, so
    // a rejected path leaves a previously running trace exactly as it was
    // instead of half-reconfigured. See ResolveConfinedOutputPath.
    std::string resolvedLogPath;
    if (!logFile.empty()) {
        std::string pathError;
        if (!ResolveConfinedOutputPath(logFile, TRACE_LOG_EXTENSIONS, resolvedLogPath, pathError)) {
            LogError("Rejected trace log path '%s': %s", logFile.c_str(), pathError.c_str());
            std::stringstream err;
            err << "\"error\":\"" << JsonEscape(pathError) << "\"";
            return BuildJsonResponse(false, err.str());
        }
    }

    InitTraceLocks();
    EnterCriticalSection(&g_traceLock);

    // Parse options
    g_traceState.traceInto = ExtractIntField(request, "trace_into", 1) != 0;
    int requestedMax = ExtractIntField(request, "max_entries", 100000);
    // maxEntries is unsigned, so a negative request used to become an enormous
    // positive value and survive only because the cap below happened to catch
    // it. Clamp at the signed boundary instead of relying on wraparound.
    if (requestedMax < 1) requestedMax = 1;
    g_traceState.maxEntries = (uint64_t)requestedMax;

    // Cap max entries
    if (g_traceState.maxEntries > 1000000) g_traceState.maxEntries = 1000000;

    // Clear previous trace
    g_traceState.entries.clear();
    g_traceState.startTime = GetTickCount64();
    g_traceState.enabled = true;

    // Handle leak: START_TRACE may legitimately be called twice in a row (the
    // caller re-arming a trace), and the second call used to overwrite a live
    // logFileHandle without closing it. That leaks a FILE* and, worse, leaves
    // the previous log file open for writing for the lifetime of x64dbg, so it
    // can never be moved or deleted. Close whatever is open first.
    if (g_traceState.logFileHandle) {
        fclose(g_traceState.logFileHandle);
        g_traceState.logFileHandle = nullptr;
    }
    g_traceState.logFile.clear();

    // Open log file if specified (path already confined above)
    if (!resolvedLogPath.empty()) {
        g_traceState.logFile = resolvedLogPath;
        g_traceState.logFileHandle = fopen(resolvedLogPath.c_str(), "w");
        if (g_traceState.logFileHandle) {
            fprintf(g_traceState.logFileHandle, "# Trace started at %llu\n", g_traceState.startTime);
            fprintf(g_traceState.logFileHandle, "# Format: timestamp,address,module,instruction,thread_id\n");
        } else {
            LogError("Could not open confined trace log '%s'", resolvedLogPath.c_str());
        }
    }

    LeaveCriticalSection(&g_traceLock);

    LogInfo("Trace started (trace_into=%d, max=%llu)", g_traceState.traceInto, g_traceState.maxEntries);

    std::stringstream data;
    data << "\"message\":\"Trace started\","
         << "\"trace_into\":" << (g_traceState.traceInto ? "true" : "false") << ","
         << "\"max_entries\":" << g_traceState.maxEntries;
    // Report the path actually used, not the one requested -- the caller asked
    // for a name and F-27 confinement decided where it landed.
    if (!resolvedLogPath.empty()) {
        data << ",\"log_file\":\"" << JsonEscape(resolvedLogPath) << "\"";
    }

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

    // A negative offset is fed to `for (size_t i = offset; ...)` below, where
    // the sign-conversion turns e.g. -1 into SIZE_MAX. That happens to be safe
    // today only because the loop condition `i < entries.size()` then fails
    // immediately -- it is correct by accident, and it stops being correct the
    // moment anyone indexes with `offset` before comparing. Clamp explicitly.
    if (offset < 0) offset = 0;

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
    snprintf(cmd, sizeof(cmd), "bp %llx", (unsigned long long)address);
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

    LogInfo("API breakpoint set: %s at 0x%llx", apiName.c_str(), (unsigned long long)address);

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

    // Clamp before the size_t conversion in the loop below -- see the identical
    // note in HandleGetTraceData.
    if (offset < 0) offset = 0;

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

// PHASE 4: STRING & PATTERN SEARCH HANDLERS

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

    // Validate. The lower bound is load-bearing: ExtractIntField uses sscanf
    // %d and accepts negatives, and a negative size would convert to a huge
    // size_t in std::vector<unsigned char> buffer(size) below, throwing
    // std::length_error. With no exception boundary that terminates x64dbg.
    if (size <= 0 || size > 10 * 1024 * 1024) {
        return BuildJsonResponse(false, "\"error\":\"Invalid size (must be 1 to 10MB)\"");
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

    // Validate size. Lower bound is load-bearing -- a negative size reaches
    // std::vector<unsigned char> buffer(size) below and throws
    // std::length_error, which with no exception boundary crashes x64dbg.
    if (size <= 0 || size > 100 * 1024 * 1024) {
        return BuildJsonResponse(false, "\"error\":\"Invalid size (must be 1 to 100MB)\"");
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
    snprintf(cmd, sizeof(cmd), "findallmem %llx", (unsigned long long)targetAddr);

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

// PHASE 5: ANTI-DEBUG BYPASS HANDLERS

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

    LogInfo("Patched debug check at 0x%llx with %s", (unsigned long long)address, patchType.c_str());

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

// PHASE 6: CODE COVERAGE HANDLERS

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

    // Clamp before the size_t conversion in the loop below -- see the identical
    // note in HandleGetTraceData.
    if (offset < 0) offset = 0;

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

    // F-27: `file` arrives straight from the request. Confine it to the plugin
    // output directory before anything opens it -- see ResolveConfinedOutputPath
    // for why prefix-after-canonicalisation is the control that matters here.
    std::string resolvedPath;
    std::string pathError;
    if (!ResolveConfinedOutputPath(filePath, COVERAGE_OUTPUT_EXTENSIONS, resolvedPath, pathError)) {
        LogError("Rejected coverage export path '%s': %s", filePath.c_str(), pathError.c_str());
        std::stringstream err;
        err << "\"error\":\"" << JsonEscape(pathError) << "\"";
        return BuildJsonResponse(false, err.str());
    }

    // Reject an unknown format before creating the file. The old code opened
    // (and therefore truncated) the target first and only then discovered the
    // format was invalid, so a bad request still destroyed the file's contents.
    if (format != "csv" && format != "json" && format != "drcov") {
        return BuildJsonResponse(false, "\"error\":\"Invalid format (use csv, json, or drcov)\"");
    }

    InitCoverageLock();
    EnterCriticalSection(&g_coverageLock);

    FILE* file = fopen(resolvedPath.c_str(), "w");
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
            (unsigned long long)mainBase, (unsigned long long)(mainBase + mainSize),
            (unsigned long long)mainBase, mainModule);

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

    LogInfo("Exported %zu coverage entries to %s", entryCount, resolvedPath.c_str());

    std::stringstream data;
    data << "\"message\":\"Coverage exported\","
         << "\"file\":\"" << JsonEscape(resolvedPath) << "\","
         << "\"format\":\"" << format << "\","
         << "\"entries\":" << entryCount;

    return BuildJsonResponse(true, data.str());
}

// EVENT HANDLERS

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

// DEBUG EVENT CALLBACKS
// These are called by x64dbg when debug events occur

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

// ---------------------------------------------------------------------------
// EXECUTE_COMMAND gate -- AUTHORITATIVE. Allowlist, fails closed.
//
// What this used to be, and why it was replaced (audit findings F-4 / F-9):
//
// F-4: this was a ~19-entry DENYLIST (BLOCKED_COMMAND_PREFIXES) that was
// byte-identical to _BLOCKED_COMMANDS in bridge.py, matched the same way
// (exact compare against the lowercased first token). The comment here claimed
// it was "a safety net in case the Python layer is bypassed", but a copy of a
// list is not a second control: every command absent from the Python list was
// absent from this one too. One control, described as two.
//
// F-9: worse, a denylist cannot work against this command language at all.
// x64dbg registers MULTIPLE ALIASES per command handler and the list named
// exactly one spelling of each, so any other spelling walked straight through.
// The command that STARTS a debuggee is `init` -- HandleLoadBinary below
// builds `init "<path>"` for exactly that purpose -- so one missed alias turns
// EXECUTE_COMMAND into an arbitrary-process-launch primitive on the analyst's
// own host. For a malware-analysis tool that is a cardinal-rule violation, and
// it is not fixable by adding more entries: the alias set is defined by
// x64dbg, not by us, and grows with every x64dbg release.
//
// So the gate is INVERTED. Only the commands below are executable; anything
// unrecognised is refused, including aliases nobody here has heard of. An
// unknown alias of a dangerous command now fails closed instead of open.
//
// Relationship to the Python layer: bridge.py keeps a small denylist, but it
// is NOT this control. It is a cheap early reject that produces a clear local
// error before a request crosses the pipe. It denies by name; this allows by
// name. They are deliberately different in direction and in contents, and when
// they disagree THIS list decides, because this is the last thing standing
// between a request and DbgCmdExec. Never widen this list because the Python
// list happens to permit something.
//
// Contents are derived from what this project actually issues on the command
// endpoint: the commands built by src/engines/dynamic/x64dbg/bridge.py, the
// tool-level allowlist in src/tools/dynamic_tools.py (allowed_command_prefixes),
// and the examples in x64dbg_execute_command's docstring (dis.prev, findall,
// log). Keep it tight -- every entry added here is granted to every MCP client
// and to anything that can reach the local HTTP port. In particular the trace
// CONFIGURATION commands (tracesetcommand / tracesetlog / tracesetlogfile) are
// intentionally absent: their arguments are themselves commands and file
// paths, so allowing them would re-open the hole this table closes. The trace
// EXECUTION commands (ticnd/tocnd/tibt/tobt) are present because the bridge's
// conditional-tracing methods issue them and they only resume the debuggee,
// which the dedicated run/step tools already permit.
// ---------------------------------------------------------------------------
static const char* ALLOWED_COMMANDS[] = {
    // Disassembly navigation and instruction queries (read-only)
    "dis", "disasm", "dis.prev", "dis.next", "dis.iscall", "dis.isbranch",
    "graph", "graphit",
    "dump", "sdump",

    // Search: memory, patterns, assembly, GUIDs (read-only)
    "find", "findall", "findmem", "findallmem",
    "findasm", "findguid",

    // Cross-references and module call discovery (read-only)
    "ref", "refstr", "refsearch", "refinfo", "reffindrange",
    "modcallfind",

    // Static analysis passes over the loaded module (read-only)
    "cfanalyze", "analxrefs", "analrecur", "analadv", "analyse",
    "exhandlers", "exinfo",

    // Expression evaluation and logging (read-only / output-only)
    "eval", "log", "msg",

    // Annotations: labels, comments, bookmarks. These mutate the analysis
    // database only -- never the debuggee and never the host filesystem.
    "lbl", "lblset", "lbldel", "lbllist",
    "cmt", "cmtset", "cmtdel", "cmtlist",
    "bm", "bmset", "bmdel", "bmlist",

    // Breakpoint listing / DLL breakpoints. Setting execution breakpoints goes
    // through the dedicated SET_BREAKPOINT handlers, not through here.
    "bplist", "bphitcount",
    "bpdll", "bcdll", "bpedll", "bpddll",

    // Watch expressions (bridge: add_watch / delete_watch / set_watch_*)
    "addwatch", "delwatch", "setwatchdog",
    "setwatchexpression", "setwatchname",

    // Type system (bridge: add_struct / add_type / visit_type / ...)
    "addstruct", "addunion", "addmember", "addtype",
    "visittype", "sizeoftype", "removetype",
    "enumtypes", "cleartypes", "loadtypes", "parsetypes",

    // Debugger variables (bridge: set_variable / delete_variable / list_variables)
    "var", "vardel", "varlist",

    // Debuggee privilege toggles (bridge: enable_privilege / disable_privilege).
    // These act on the DEBUGGEE's token, not on the debugger, and are exposed
    // by dedicated tools already.
    "enableprivilege", "disableprivilege",

    // Execution control that the bridge issues on this endpoint: run-to-user
    // code, single-instruction undo, and conditional/record tracing.
    "rtu", "instrundo",
    "ticnd", "tocnd", "tibt", "tobt",
    "tracesetcondition",

    nullptr  // sentinel
};

// ---------------------------------------------------------------------------
// Finding F-16 (plugin side) -- the gate matched ONE token, DbgCmdExec runs
// MANY commands.
//
// x64dbg's command dispatcher treats ';' as a command separator, so a single
// string handed to DbgCmdExec is a command LIST, not a command. The gate used
// to lowercase the first word of the whole string, look that up, and let the
// entire string through on the strength of it. So:
//
//     "bplist; init \"C:\\\\evil.exe\""
//
// passed the allowlist on `bplist` and then executed `init` -- precisely the
// arbitrary-process-launch primitive that inverting this gate (F-9) existed to
// prevent, reachable through the gate rather than around it.
//
// The gate is therefore applied to EVERY ';'-separated segment. A command list
// is admitted only if every one of its members is independently admissible.
//
// Two deliberate over-rejections, both fail-closed:
//   * a trailing or doubled ';' yields an empty segment, which is refused
//     rather than skipped -- "allowed; " is not worth a special case, and
//     skipping empties is the kind of leniency that grows into a bypass;
//   * a ';' inside a quoted argument (log "a;b") is still treated as a
//     separator, because this code does not model x64dbg's quoting rules and
//     guessing them wrong in the permissive direction is how gates fail.
// ---------------------------------------------------------------------------

// Match ONE already-split command segment against ALLOWED_COMMANDS.
// Every path that is not an exact table hit returns false.
static bool IsCommandSegmentAllowed(const std::string& segment) {
    // Skip leading whitespace so "log x; bplist" matches on "bplist", not " bplist".
    size_t begin = 0;
    while (begin < segment.size() && (segment[begin] == ' ' || segment[begin] == '\t')) {
        begin++;
    }

    // Fail closed: an empty segment is not "no command", it is an unparsed one.
    if (begin >= segment.size()) {
        return false;
    }

    // A leading '$' makes x64dbg parse the line as an expression/assignment
    // instead of a registered command, so it would never match a table entry --
    // but it must be refused explicitly rather than left to fall off the end of
    // the table, because the whole point of this function is that the reason a
    // string is refused is legible.
    if (segment[begin] == '$') {
        return false;
    }

    // Extract first word, lowercased. The terminator set matches x64dbg's
    // argument syntax so that both "findall 0, E8" and the function-call form
    // "dis.prev(rip, 5)" reduce to their command name.
    std::string firstWord;
    for (size_t i = begin; i < segment.size(); i++) {
        char c = segment[i];
        if (c == ' ' || c == '\t' || c == '(' || c == ',') break;
        firstWord += (char)tolower((unsigned char)c);
    }

    // Fail closed: an empty token is not "no command", it is an unparsed one.
    if (firstWord.empty()) {
        return false;
    }

    for (int i = 0; ALLOWED_COMMANDS[i] != nullptr; i++) {
        if (firstWord == ALLOWED_COMMANDS[i]) {
            return true;
        }
    }
    return false;
}

// Returns true only if EVERY ';'-separated segment of the command is on
// ALLOWED_COMMANDS. Every other input -- unknown command, unknown alias, empty
// string, anything carrying an embedded line break -- is refused.
static bool IsCommandAllowed(const std::string& command) {
    // x64dbg's script engine is line-oriented, so a CR/LF is a command
    // separator this function does not split on, and an embedded NUL truncates
    // the string differently for strlen-based consumers than for std::string.
    // None of the three is ever legitimate here -- reject outright rather than
    // trying to parse what the rest of the line would mean.
    for (size_t i = 0; i < command.size(); i++) {
        unsigned char c = (unsigned char)command[i];
        if (c == '\n' || c == '\r' || c == '\0') {
            return false;
        }
    }

    // F-16: check every ';'-separated segment, not just the first.
    size_t start = 0;
    while (start <= command.size()) {
        size_t end = command.find(';', start);
        std::string segment = (end == std::string::npos)
                                  ? command.substr(start)
                                  : command.substr(start, end - start);
        if (!IsCommandSegmentAllowed(segment)) {
            return false;
        }
        if (end == std::string::npos) {
            return true;
        }
        start = end + 1;
    }

    // Default branch. Reached only if the loop is ever restructured such that
    // it can fall out; a gate's fall-through must be a rejection.
    return false;
}

// Handler: EXECUTE_COMMAND - Execute a validated x64dbg command
std::string HandleExecuteCommand(const std::string& request) {
    std::string command = ExtractStringField(request, "command");
    if (command.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing command parameter\"");
    }

    if (!DbgIsDebugging()) {
        return BuildJsonResponse(false, "\"error\":\"Not debugging - load a binary first\"");
    }

    // Authoritative gate (findings F-4 / F-9): allowlist, fails closed.
    // Refuse with a JSON error rather than throwing or aborting -- the pipe
    // server expects a well-formed response for every request, and a refused
    // command is a normal outcome, not a fault.
    if (!IsCommandAllowed(command)) {
        LogInfo("Blocked command (not on allowlist): %s", command.c_str());
        return BuildJsonResponse(false,
            "\"error\":\"Command blocked by security policy: not on the allowlist "
            "of permitted analysis commands\"");
    }

    LogInfo("Executing command: %s", command.c_str());

    if (DbgCmdExec(command.c_str())) {
        std::stringstream data;
        data << "\"command\":\"" << JsonEscape(command) << "\","
             << "\"executed\":true";
        return BuildJsonResponse(true, data.str());
    } else {
        std::stringstream data;
        data << "\"error\":\"Command failed: " << JsonEscape(command) << "\"";
        return BuildJsonResponse(false, data.str());
    }
}

// AUDIT (command-string injection into DbgCmdExec): HandleLoadBinary builds
//
//     init "<path>", "<arguments>", "<working_directory>"
//
// by string concatenation, with no escaping of any of the three fields. x64dbg
// has no escape syntax inside a quoted command argument, so a field containing
// a double quote CLOSES the quote and everything after it is reparsed as
// command syntax -- and ';' then starts a whole new command. A `path` of
//
//     C:\a.exe";bplist;init "C:\evil.exe
//
// therefore executes commands the caller never named, straight past the
// EXECUTE_COMMAND allowlist, because this handler is not the command endpoint.
//
// There is no correct way to escape these for x64dbg, so the only sound answer
// is to refuse the characters that make reparsing possible: the quote itself,
// a backslash immediately before a quote (which some parsers treat as an
// escaped quote and which is never meaningful at the end of a Windows path),
// the ',' argument separator, and any control character (CR/LF terminate the
// command line outright). Legitimate Windows paths and working directories
// never contain any of them.
static bool ContainsCommandMetacharacters(const std::string& value) {
    for (size_t i = 0; i < value.size(); i++) {
        unsigned char c = (unsigned char)value[i];
        if (c < 0x20 || c == 0x7F) return true;   // controls, incl. CR/LF/NUL/DEL
        if (c == '"' || c == ',' || c == ';') return true;
        if (c == '\\' && i + 1 < value.size() && value[i + 1] == '"') return true;
    }
    return false;
}

// Handler: LOAD_BINARY - Load binary into debugger
std::string HandleLoadBinary(const std::string& request) {
    std::string path = ExtractStringField(request, "path");
    std::string args = ExtractStringField(request, "arguments");
    std::string workingDir = ExtractStringField(request, "working_directory");

    if (path.empty()) {
        return BuildJsonResponse(false, "\"error\":\"Missing path\"");
    }

    // See ContainsCommandMetacharacters above: all three fields are interpolated
    // into a quoted x64dbg command string that has no escape syntax.
    if (ContainsCommandMetacharacters(path) ||
        ContainsCommandMetacharacters(args) ||
        ContainsCommandMetacharacters(workingDir)) {
        LogError("Rejected LOAD_BINARY: field contains x64dbg command metacharacters");
        return BuildJsonResponse(false,
            "\"error\":\"path, arguments and working_directory may not contain "
            "quotes, commas, semicolons or control characters\"");
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

// Forward declaration: the pipe DACL is built with the same helper as the auth
// token file's, which is defined further down next to pluginSetup (F-15/F-17).
static bool BuildCurrentUserOnlySecurity(SECURITY_ATTRIBUTES& sa, PSECURITY_DESCRIPTOR& outSd);

// Close the pipe instance. PipeServerThread is the ONLY caller -- see the
// ownership comment on pluginStop -- and it takes g_pipeHandleLock so that a
// concurrent CancelIoEx from pluginStop can never be issued on a handle that
// has already been closed (or, far worse, on a recycled handle value that by
// then names something else entirely).
static void ClosePipeServerHandle() {
    if (g_pipeHandleLockInit) EnterCriticalSection(&g_pipeHandleLock);
    if (g_pipeServer != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipeServer);
        g_pipeServer = INVALID_HANDLE_VALUE;
    }
    if (g_pipeHandleLockInit) LeaveCriticalSection(&g_pipeHandleLock);
}

// ---------------------------------------------------------------------------
// Finding F-17 -- the named pipe had NO authentication and the wrong DACL.
//
// The pipe is the plugin's real control surface: every request that reaches the
// switch below can read and WRITE debuggee memory, run x64dbg commands and load
// binaries. The bearer token that supposedly protects all that is checked in
// obsidian_server.exe -- on the HTTP side -- and never here. So anything that
// could open \\.\pipe\x64dbg_mcp was already past authentication.
//
// Who could open it? CreateNamedPipeA was called with nullptr security
// attributes, i.e. the process default DACL, which grants access to any process
// running as the same user. On a malware-analysis workstation the debuggee is
// normally started BY x64dbg AS THE SAME USER. The sample under analysis could
// therefore connect to this pipe and drive WRITE_MEMORY / EXECUTE_COMMAND /
// LOAD_BINARY against its own debugger with no token at all -- the trust
// boundary ran the wrong way round.
//
// Three changes, all of them necessary:
//   1. PIPE_REJECT_REMOTE_CLIENTS -- named pipes are reachable over SMB, so
//      without this the surface is not even local.
//   2. An explicit DACL naming only the current user, replacing the default.
//      This is defence in depth, not the fix: it does not exclude the debuggee,
//      which runs as that same user. Item 3 is the fix.
//   3. Peer authentication on every connection: GetNamedPipeClientProcessId,
//      compared against the PID of the obsidian_server.exe this plugin spawned.
//      Anything else is disconnected before a single byte is read.
//
// On PID reuse: the comparison is sound because the plugin holds an open handle
// to that process (g_serverProcess) for its whole lifetime, and Windows cannot
// recycle a PID while a handle to the process is open. A zero g_serverProcessId
// means no server has been spawned yet, which is a reject, not a bypass.
// ---------------------------------------------------------------------------
static bool IsPipeClientAuthorised(HANDLE pipe) {
    ULONG clientPid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &clientPid)) {
        LogError("Rejecting pipe client: GetNamedPipeClientProcessId failed (%d)", GetLastError());
        return false;
    }

    DWORD expectedPid = g_serverProcessId.load();
    if (expectedPid == 0) {
        LogError("Rejecting pipe client PID %lu: no Obsidian server has been spawned yet",
                 (unsigned long)clientPid);
        return false;
    }

    if ((DWORD)clientPid != expectedPid) {
        LogError("Rejecting pipe client PID %lu: expected the spawned Obsidian server (PID %lu)",
                 (unsigned long)clientPid, (unsigned long)expectedPid);
        return false;
    }

    return true;
}

// Named Pipe server thread (handles requests from HTTP server process)
static DWORD WINAPI PipeServerThread(LPVOID lpParam) {
    LogInfo("Named Pipe server thread starting...");

    // Signal g_pipeReadyEvent exactly once, on the first pipe instance.
    // pluginSetup closes that event as soon as its 5-second wait returns, so
    // touching it on a LATER iteration would be a use-after-close -- and later
    // iterations are now routine, because F-17 recreates the instance every
    // time an unauthorised peer is turned away.
    bool signalledReady = false;

    while (g_running) {
        // F-17: explicit user-only DACL instead of the process default.
        SECURITY_ATTRIBUTES pipeSa;
        PSECURITY_DESCRIPTOR pipeSd = nullptr;
        bool havePipeSecurity = BuildCurrentUserOnlySecurity(pipeSa, pipeSd);
        if (!havePipeSecurity) {
            LogError("Could not build restrictive DACL for the pipe: %d "
                     "(falling back to default security; peer PID check still applies)",
                     GetLastError());
        }

        // Create named pipe instance with FILE_FLAG_OVERLAPPED for async operations
        HANDLE pipe = CreateNamedPipeA(
            Protocol::PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            // F-17: PIPE_REJECT_REMOTE_CLIENTS -- without it this pipe is
            // openable across SMB by anything that can authenticate to the box.
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,  // Max instances
            Protocol::MAX_MESSAGE_SIZE,
            Protocol::MAX_MESSAGE_SIZE,
            0,
            havePipeSecurity ? &pipeSa : nullptr
        );

        // The descriptor is copied into the object at creation time.
        if (pipeSd) {
            LocalFree(pipeSd);
            pipeSd = nullptr;
        }

        if (pipe == INVALID_HANDLE_VALUE) {
            LogError("Failed to create named pipe: %d", GetLastError());
            return 1;
        }
        // Publish the handle UNDER THE LOCK (CWE-362). pluginStop reads
        // g_pipeServer while holding g_pipeHandleLock and calls CancelIoEx /
        // DisconnectNamedPipe on it; ClosePipeServerHandle clears it under the
        // same lock. This assignment was the one access that did neither, so
        // the invariant pluginStop's comment asserts -- that the handle cannot
        // change under it mid-call -- did not actually hold, and g_pipeServer
        // is a plain static a compiler is free to cache.
        //
        // Practical effect of the old race was bounded (pluginStop could see
        // INVALID_HANDLE_VALUE, skip the cancel, and rely on g_running plus
        // g_shutdownEvent to unwind the thread) but it was still a data race,
        // and "bounded today" is not a property that survives edits.
        if (g_pipeHandleLockInit) EnterCriticalSection(&g_pipeHandleLock);
        g_pipeServer = pipe;
        if (g_pipeHandleLockInit) LeaveCriticalSection(&g_pipeHandleLock);

        // Signal that pipe is ready for server to connect (first instance only)
        if (!signalledReady && g_pipeReadyEvent) {
            SetEvent(g_pipeReadyEvent);
            signalledReady = true;
        }

        LogInfo("Waiting for HTTP server to connect...");

        // Use overlapped I/O for interruptible ConnectNamedPipe
        OVERLAPPED overlapped = {};
        overlapped.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
        if (!overlapped.hEvent) {
            // AUDIT: this CreateEventA was unchecked. A NULL hEvent makes the
            // WaitForMultipleObjects below return WAIT_FAILED, and the old
            // else-branch read any non-WAIT_OBJECT_0 result as "shutdown
            // requested" -- so an event-creation failure silently tore the
            // bridge down and reported it as a clean shutdown.
            LogError("Failed to create pipe connect event: %d", GetLastError());
            ClosePipeServerHandle();
            return 1;
        }

        BOOL connected = ConnectNamedPipe(g_pipeServer, &overlapped);
        DWORD error = GetLastError();

        if (!connected && error == ERROR_IO_PENDING) {
            // Wait for connection or shutdown event
            HANDLE waitHandles[2] = { overlapped.hEvent, g_shutdownEvent };
            DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

            if (waitResult == WAIT_OBJECT_0) {
                // Connection succeeded
                LogInfo("HTTP server connected to pipe");
            } else if (waitResult == WAIT_OBJECT_0 + 1) {
                // Shutdown event signaled
                CancelIo(g_pipeServer);
                CloseHandle(overlapped.hEvent);
                ClosePipeServerHandle();
                LogInfo("Pipe server thread shutting down (no connection)");
                return 0;
            } else {
                // WAIT_FAILED / WAIT_ABANDONED. Distinguished from shutdown so
                // the log says what actually happened (see the CreateEventA
                // note above); either way the wait handles are untrustworthy,
                // so stop rather than spin.
                LogError("Pipe connect wait failed: result=%lu error=%d",
                         (unsigned long)waitResult, GetLastError());
                CancelIo(g_pipeServer);
                CloseHandle(overlapped.hEvent);
                ClosePipeServerHandle();
                return 1;
            }
        } else if (!connected && error != ERROR_PIPE_CONNECTED) {
            LogError("ConnectNamedPipe failed: %d", error);
            CloseHandle(overlapped.hEvent);
            ClosePipeServerHandle();
            continue;
        } else {
            LogInfo("HTTP server connected to pipe");
        }

        CloseHandle(overlapped.hEvent);

        // F-17: authenticate the peer BEFORE dispatching anything. A rejected
        // client is disconnected and the instance recreated, so a hostile
        // process cannot hold the single pipe instance open to lock the real
        // server out either.
        if (!IsPipeClientAuthorised(g_pipeServer)) {
            DisconnectNamedPipe(g_pipeServer);
            ClosePipeServerHandle();
            continue;
        }

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
                // AUDIT (oversized message killed the bridge): this used to
                // `break`, which tears down the connection. The HTTP server
                // treats a lost pipe as fatal and exits, so ONE oversized
                // request permanently disabled the bridge until x64dbg was
                // restarted -- a denial of service out of a malformed frame.
                //
                // Instead: drain the oversized message off the pipe so the
                // stream stays framed, reply with an error, and carry on. The
                // pipe is in message mode, so ReadFile returns ERROR_MORE_DATA
                // for each chunk of the message that does not fit and succeeds
                // on the last one; the iteration bound stops a peer that
                // announces a huge length and then dribbles it forever.
                LogError("Request too large: %u bytes (draining)", requestLength);

                bool drained = false;
                char drainBuffer[8192];
                const int MAX_DRAIN_CHUNKS = 4096;  // 32 MiB of dribble, then give up
                for (int chunk = 0; chunk < MAX_DRAIN_CHUNKS; chunk++) {
                    DWORD drainRead = 0;
                    if (ReadFile(g_pipeServer, drainBuffer, (DWORD)sizeof(drainBuffer), &drainRead, nullptr)) {
                        drained = true;   // final chunk of the message
                        break;
                    }
                    if (GetLastError() != ERROR_MORE_DATA) {
                        break;            // broken pipe or a real error
                    }
                }

                if (!drained) {
                    LogError("Could not drain oversized request; dropping connection");
                    break;
                }

                std::string tooLarge = BuildJsonResponse(false,
                    "\"error\":\"Request exceeds the maximum message size\"");
                uint32_t tooLargeLength = static_cast<uint32_t>(tooLarge.size());
                DWORD tooLargeWritten = 0;
                if (!WriteFile(g_pipeServer, &tooLargeLength, sizeof(tooLargeLength), &tooLargeWritten, nullptr) ||
                    !WriteFile(g_pipeServer, tooLarge.c_str(), tooLargeLength, &tooLargeWritten, nullptr)) {
                    LogError("Failed to report oversized request: %d", GetLastError());
                    break;
                }
                continue;
            }

            // A zero-length frame carries nothing to dispatch, and
            // std::vector<char>(0).data() may be null -- constructing a string
            // from a null pointer is UB even with a zero count. Answer and
            // carry on rather than tearing the connection down.
            if (requestLength == 0) {
                LogError("Empty request frame; ignoring");
                continue;
            }

            // Read request data
            std::vector<char> buffer(requestLength);
            bytesRead = 0;
            if (!ReadFile(g_pipeServer, buffer.data(), requestLength, &bytesRead, nullptr)) {
                LogError("Failed to read request: %d", GetLastError());
                break;
            }

            // Use what was ACTUALLY read, not what the length prefix promised
            // (CWE-252). The two differ on a short read, and building the
            // string from requestLength then tacked the vector's zero-filled
            // tail onto the JSON. Not an info leak -- std::vector<char>(n)
            // value-initialises -- but the parser saw a frame the peer never
            // sent.
            if (bytesRead != requestLength) {
                LogError("Short request frame: expected %u bytes, got %lu",
                         requestLength, (unsigned long)bytesRead);
            }

            std::string request(buffer.data(), bytesRead);
            LogInfo("Received request: %s", request.c_str());

            // Parse request type and route to appropriate handler
            std::string response;
            int requestType = ExtractIntField(request, "type", -1);

            if (requestType == -1) {
                response = BuildJsonResponse(false, "\"error\":\"Missing 'type' field\"");
            } else {
                LogInfo("Request type: %d", requestType);

                // Route to appropriate handler. Wrapped in try/catch because a
                // handler that throws -- e.g. std::length_error / std::bad_alloc
                // from a std::vector sized by attacker-controlled input -- would
                // otherwise unwind out of PipeServerThread and terminate the
                // entire x64dbg process, killing the debugging session. A bad
                // request must cost one error reply, not the whole session.
                // (audit P2: the exception boundary the plugin lacked.)
                try {
                switch (requestType) {
                    // Core debugger state
                    case GET_STATE:
                        response = HandleGetState(request);
                        break;
                    case LOAD_BINARY:
                        response = HandleLoadBinary(request);
                        break;
                    case EXECUTE_COMMAND:
                        response = HandleExecuteCommand(request);
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
                } catch (const std::exception& e) {
                    LogError("Handler threw exception: %s", e.what());
                    response = BuildJsonResponse(false, "\"error\":\"Internal handler error\"");
                } catch (...) {
                    LogError("Handler threw unknown exception");
                    response = BuildJsonResponse(false, "\"error\":\"Internal handler error\"");
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

        // Disconnect client. ClosePipeServerHandle (not a bare CloseHandle) so
        // the close is serialised against pluginStop's CancelIoEx.
        DisconnectNamedPipe(g_pipeServer);
        ClosePipeServerHandle();
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
    snprintf(serverPath, MAX_PATH, "%sobsidian_server.exe", pluginPath);

    // Verify server executable exists before attempting to spawn
    DWORD fileAttrib = GetFileAttributesA(serverPath);
    if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
        LogError("Server executable not found: %s", serverPath);
        LogError("Make sure obsidian_server.exe is in the same directory as the plugin");
        LogError("GetFileAttributes error: %d", GetLastError());
        return false;
    }

    LogInfo("Spawning Obsidian server: %s", serverPath);

    // Build command line (lpCommandLine must be writable per MSDN)
    char cmdLine[MAX_PATH + 2];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", serverPath);

    // Spawn process
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(
        nullptr,       // lpApplicationName: NULL so lpCommandLine is used
        cmdLine,       // Command line (writable buffer, quoted for spaces)
        nullptr,       // Process attributes
        nullptr,       // Thread attributes
        FALSE,         // Inherit handles
        CREATE_NEW_CONSOLE,  // Explicitly create console window for server diagnostics
        nullptr,       // Environment
        pluginPath,    // Current directory: plugin directory
        &si,
        &pi
    )) {
        DWORD err = GetLastError();
        LogError("Failed to spawn Obsidian server (error %d)", err);
        if (err == 740) {
            LogError("Error 740: Elevation required. Try running x64dbg as Administrator.");
        } else if (err == 2) {
            LogError("Error 2: File not found. Check that obsidian_server.exe exists.");
        } else if (err == 5) {
            LogError("Error 5: Access denied. Smart App Control or antivirus may be blocking the executable.");
        } else if (err == 1260) {
            LogError("Error 1260: Blocked by group policy or Smart App Control.");
        }
        return false;
    }

    g_serverProcess = pi.hProcess;
    // F-17: record the PID the pipe peer must match. g_serverProcess is kept
    // open for the plugin's lifetime, which is what makes this PID stable --
    // Windows will not recycle a PID while a handle to the process is open, so
    // "client PID == g_serverProcessId" cannot be satisfied by an impostor that
    // waited for the real server to exit.
    g_serverProcessId.store(pi.dwProcessId);
    CloseHandle(pi.hThread);  // Don't need thread handle

    // Clear token from environment immediately after spawn (child already inherited it)
    SetEnvironmentVariableA("OBSIDIAN_AUTH_TOKEN", nullptr);

    // Verify the process is still alive after a brief moment
    // (catches immediate crashes from missing DLLs, Smart App Control blocks, etc.)
    Sleep(250);
    DWORD exitCode = 0;
    if (GetExitCodeProcess(g_serverProcess, &exitCode) && exitCode != STILL_ACTIVE) {
        LogError("Server process exited immediately with code %d", exitCode);
        if (exitCode == 0xC0000135) {
            LogError("Exit code 0xC0000135: Missing DLL dependency (install Visual C++ Redistributable)");
        } else if (exitCode == 0xC0000142) {
            LogError("Exit code 0xC0000142: DLL initialization failed");
        } else if (exitCode == 1) {
            LogError("Server returned error 1 - check: pipe connection, auth token file, or port 8765 in use");
        }
        // F-17: the handle that pinned this PID is about to be closed, so the
        // PID may be recycled. Clear it, or the pipe would authorise whatever
        // process next receives that PID.
        g_serverProcessId.store(0);
        CloseHandle(g_serverProcess);
        g_serverProcess = nullptr;
        return false;
    }

    LogInfo("HTTP server process started and verified (PID: %d)", pi.dwProcessId);
    LogInfo("Server log file: %sobsidian_server.log", pluginPath);
    return true;
}

// Menu callback handler (handles all menu entries)
void MenuEntryCallback(CBTYPE cbType, PLUG_CB_MENUENTRY* info) {
    switch (info->hEntry) {
        case 0: {  // About
            char aboutMsg[1024];
            snprintf(aboutMsg, sizeof(aboutMsg),
                "Obsidian - AI-Powered Debugging Bridge\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                "Version: %s\n"
                "Author: %s\n\n"
                "Obsidian provides MCP (Model Context Protocol) integration\n"
                "for x64dbg, enabling AI assistants to control and analyze\n"
                "debugging sessions in real-time.\n\n"
                "Features:\n"
                "  • Live debugging control & breakpoint management\n"
                "  • Memory inspection & modification\n"
                "  • Instruction tracing & API logging\n"
                "  • Anti-debug bypass capabilities\n"
                "  • Code coverage analysis\n\n"
                "Architecture:\n"
                "  • Named Pipe IPC (plugin ↔ server)\n"
                "  • HTTP REST API on port 8765\n"
                "  • Crash-isolated external process\n\n"
                "Website: %s",
                PLUGIN_VERSION_STR,
                PLUGIN_AUTHOR,
                PLUGIN_WEBSITE
            );
            MessageBoxA(
                nullptr,
                aboutMsg,
                "About Obsidian",
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
                "Obsidian Status\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                "Plugin State:  %s\n"
                "Named Pipe:    %s\n"
                "HTTP Server:   %s\n"
                "Server PID:    %lu\n\n"
                "Endpoints:\n"
                "  Pipe: \\\\.\\pipe\\x64dbg_mcp\n"
                "  HTTP: http://127.0.0.1:8765",
                g_running ? "Running" : "Stopped",
                pipeStatus,
                serverStatus,
                serverPid
            );

            MessageBoxA(nullptr, statusMsg, "Obsidian Status", MB_OK | MB_ICONINFORMATION);
            break;
        }
    }
}

// Plugin initialization
bool pluginInit(PLUG_INITSTRUCT* initStruct) {
    g_pluginHandle = initStruct->pluginHandle;

    // Initialise the pipe-handle lock here: x64dbg calls pluginit once, on one
    // thread, before the pipe thread exists. Doing it lazily from whichever
    // thread got there first would be the very race the lock exists to close.
    if (!g_pipeHandleLockInit) {
        InitializeCriticalSection(&g_pipeHandleLock);
        g_pipeHandleLockInit = true;
    }

    LogInfo("Initializing Obsidian v%s", PLUGIN_VERSION_STR);
    return true;
}

// How long pluginStop is willing to wait for PipeServerThread to leave this
// DLL's code. It must exceed the longest uninterruptible span in that thread.
// With the F-20 fix the wait handlers abort within one 50 ms poll interval, and
// the only other blocking calls are pipe I/O that CancelIoEx unblocks, so 10 s
// is generous rather than tight -- and the point of being generous is that the
// timeout branch below is a genuine last resort, not a routine occurrence.
static const DWORD PIPE_THREAD_SHUTDOWN_TIMEOUT_MS = 10000;

void pluginStop() {
    LogInfo("Stopping plugin");

    // Stop pipe server
    g_running = false;

    // Signal shutdown event to wake up pipe thread. This is what pulls the
    // WAIT_PAUSED / WAIT_RUNNING / WAIT_DEBUGGING poll loops out early (F-20).
    if (g_shutdownEvent) {
        SetEvent(g_shutdownEvent);
    }

    // Unblock any pipe I/O the thread is sitting in, WITHOUT closing the handle.
    //
    // AUDIT (handle-recycling race / double close): this used to
    // CloseHandle(g_pipeServer) from here while PipeServerThread was inside
    // ReadFile/WriteFile on that same handle and would itself CloseHandle it on
    // the way out. Two threads closing one handle is a double close, and the
    // window between the close here and the thread's next use of g_pipeServer
    // is a window in which Windows can hand that numeric handle value to a
    // completely unrelated object -- the thread would then read from, write to,
    // or close whatever that turned out to be.
    //
    // Ownership is now unambiguous: PipeServerThread creates and closes the
    // handle, and nobody else ever closes it. pluginStop may only CANCEL I/O on
    // it, under g_pipeHandleLock so the handle cannot be closed mid-call.
    // CancelIoEx (not CancelIo) is required because it cancels operations
    // issued by OTHER threads.
    if (g_pipeHandleLockInit) {
        EnterCriticalSection(&g_pipeHandleLock);
        if (g_pipeServer != INVALID_HANDLE_VALUE) {
            CancelIoEx(g_pipeServer, nullptr);
            DisconnectNamedPipe(g_pipeServer);
        }
        LeaveCriticalSection(&g_pipeHandleLock);
    }

    // Wait for the pipe thread to exit.
    //
    // F-20: this used to wait 1000 ms and then carry on regardless. Carrying on
    // means returning from plugstop(), which is x64dbg's cue to FreeLibrary
    // this DLL -- while a thread is still running inside it. That is a
    // use-after-free of the plugin image, and it was reachable from a plain
    // request because the wait handlers could block for five minutes.
    //
    // So: wait long enough for the handshake above to work, and if the thread
    // STILL has not exited, do not let the unload happen. Pinning the module
    // (GET_MODULE_HANDLE_EX_FLAG_PIN) makes the loader ignore the FreeLibrary,
    // deliberately leaking this DLL's image, its thread handle and its events
    // for the remaining life of the process. Leaking is the correct trade:
    // a leaked mapping costs memory, executing freed code costs control of the
    // process.
    if (g_pipeThread) {
        DWORD waitResult = WaitForSingleObject(g_pipeThread, PIPE_THREAD_SHUTDOWN_TIMEOUT_MS);
        if (waitResult != WAIT_OBJECT_0) {
            LogError("Pipe thread did not exit within %lu ms (wait result %lu) -- "
                     "pinning the plugin module to prevent an unload while it is still running",
                     (unsigned long)PIPE_THREAD_SHUTDOWN_TIMEOUT_MS, (unsigned long)waitResult);

            // FROM_ADDRESS wants any address inside this module; a static
            // global is used rather than a function pointer because casting a
            // function pointer to LPCSTR is only conditionally supported.
            HMODULE pinned = nullptr;
            if (!GetModuleHandleExA(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                    (LPCSTR)&g_pipeHandleLockInit,
                    &pinned)) {
                LogError("Failed to pin plugin module: %d -- unload may crash", GetLastError());
            }

            // Intentionally NOT closing g_pipeThread, g_shutdownEvent or
            // g_pipeReadyEvent: the still-running thread dereferences all three.
            // Return early so the token file and server process are left alone
            // too -- the thread may still be servicing a request against them.
            LogInfo("Plugin stopped (pipe thread still running; resources intentionally leaked)");
            return;
        }
        CloseHandle(g_pipeThread);
        g_pipeThread = nullptr;
    }

    // Cleanup events. Safe now: the pipe thread has provably exited.
    if (g_shutdownEvent) {
        CloseHandle(g_shutdownEvent);
        g_shutdownEvent = nullptr;
    }
    if (g_pipeReadyEvent) {
        CloseHandle(g_pipeReadyEvent);
        g_pipeReadyEvent = nullptr;
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
        // F-17: the PID stops being pinned the moment this handle closes.
        g_serverProcessId.store(0);
    }

    // AUDIT (dead Reset() methods): g_traceState / g_apiLogState /
    // g_coverageState / g_antiDebugState each defined a Reset() that nothing
    // ever called. Dead cleanup code is worse than none -- a reader sees it and
    // assumes teardown happens. It does matter here: g_traceState::Reset is the
    // only thing that fcloses a trace log still open at shutdown, and the state
    // objects have static storage duration, so a plugin unloaded and reloaded
    // inside one x64dbg session would otherwise resume with the previous
    // session's entries and an inherited "enabled" flag. Wire them up.
    //
    // Reached only on the clean-shutdown path: the timeout branch above returns
    // early precisely because the pipe thread may still be inside these locks.
    if (g_locksInitialized) {
        EnterCriticalSection(&g_traceLock);
        g_traceState.Reset();
        LeaveCriticalSection(&g_traceLock);

        EnterCriticalSection(&g_apiLogLock);
        g_apiLogState.Reset();
        LeaveCriticalSection(&g_apiLogLock);
    }
    if (g_coverageLockInitialized) {
        EnterCriticalSection(&g_coverageLock);
        g_coverageState.Reset();
        LeaveCriticalSection(&g_coverageLock);
    }
    g_antiDebugState.Reset();

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
//
// AUDIT (buffer-size parameter was decorative): the loop bounded itself with
// `i * 2 < tokenLength - 1` but then unconditionally wrote `outToken[64] = 0`,
// so the terminator landed at a fixed offset no matter what size the caller
// declared -- a 32-byte buffer would have been written 33 bytes past its end.
// And because tokenLength is size_t, `tokenLength - 1` UNDERFLOWS to SIZE_MAX
// when tokenLength is 0, turning the bound into "always true" and the guard
// into a no-op. Both were survivable only because there is exactly one caller
// and it passes 65; a second caller would have been an out-of-bounds write.
// Honour tokenLength properly and refuse a buffer that cannot hold the result.
static bool GenerateSecureToken(char* outToken, size_t tokenLength) {
    // 32 random bytes -> 64 hex characters, plus the terminator.
    const size_t requiredLength = 65;
    if (!outToken || tokenLength < requiredLength) {
        LogError("GenerateSecureToken: buffer of %zu bytes is too small (need %zu)",
                 tokenLength, requiredLength);
        return false;
    }

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

    // Convert to hex string (64 characters). The buffer size was validated on
    // entry, so this writes exactly indices 0..63 and terminates at 64.
    const char* hexChars = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(randomBytes); i++) {
        outToken[i * 2] = hexChars[(randomBytes[i] >> 4) & 0x0F];
        outToken[i * 2 + 1] = hexChars[randomBytes[i] & 0x0F];
    }
    outToken[sizeof(randomBytes) * 2] = '\0';

    return true;
}

// Build a SECURITY_ATTRIBUTES whose DACL grants access to the current user
// only. Two call sites: the auth-token file (F-15) and the named pipe (F-17,
// which forward-declares this function because PipeServerThread is defined
// above it). FILE_ALL_ACCESS ("FA") is the right mask for both -- the named
// pipe rights, including FILE_CREATE_PIPE_INSTANCE, are inside it.
//
// Audit finding F-15: the token file was created with nullptr security
// attributes, i.e. the process default DACL. On a normal desktop that already
// resolves to roughly "this user + SYSTEM + Administrators" and the file lives
// in the per-user %TEMP%, so the exposure was limited -- but the file contains
// the bearer token that drives this debugger, and "limited by default policy"
// is not the same as "restricted on purpose". A default DACL also inherits
// whatever the token's default owner/group happens to be, which is not
// something this plugin should be relying on.
//
// Threat that remains regardless: a sample detonated as the analyst's own user
// can read this file (and the OBSIDIAN_AUTH_TOKEN environment variable) and
// then drive x64dbg through the local HTTP API. An explicit user-only DACL
// does not stop that -- same user, same access. Detonate untrusted samples as
// a separate low-privilege principal or in a disposable VM; do not treat this
// token as a boundary against the sample itself.
//
// On success the caller owns *outSd and must LocalFree it after the file is
// created. On failure sa is left usable as "no explicit descriptor".
static bool BuildCurrentUserOnlySecurity(SECURITY_ATTRIBUTES& sa, PSECURITY_DESCRIPTOR& outSd) {
    outSd = nullptr;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = FALSE;

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    DWORD len = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &len);  // expected to fail, sizes the buffer
    if (len == 0) {
        CloseHandle(hToken);
        return false;
    }

    std::vector<char> buffer(len);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), len, &len)) {
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);

    TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPSTR sidString = nullptr;
    if (!ConvertSidToStringSidA(tokenUser->User.Sid, &sidString)) {
        return false;
    }

    // D:P              -> DACL, protected: block inherited ACEs from %TEMP%.
    // (A;;FA;;;<sid>)  -> allow FILE_ALL_ACCESS to this user's SID and nobody
    //                     else. Administrators and SYSTEM are deliberately not
    //                     listed; they can take ownership anyway, so naming
    //                     them would only widen the ACL for no gain.
    std::string sddl = "D:P(A;;FA;;;";
    sddl += sidString;
    sddl += ")";
    LocalFree(sidString);

    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        return false;
    }

    outSd = sd;
    sa.lpSecurityDescriptor = sd;
    return true;
}

void pluginSetup() {
    LogInfo("Setting up plugin");

    // Generate cryptographically secure random token (256 bits)
    char token[65];  // 64 hex chars + null terminator
    if (!GenerateSecureToken(token, sizeof(token))) {
        LogError("Failed to generate secure token");
        return;
    }

    LogInfo("Generated secure authentication token (256-bit)");

    // Pass token to server via environment variable (inherited by child process)
    // This avoids file system issues (permissions, 8.3 paths, FILE_ATTRIBUTE_TEMPORARY)
    if (!SetEnvironmentVariableA("OBSIDIAN_AUTH_TOKEN", token)) {
        LogError("Failed to set auth token environment variable: %d", GetLastError());
        return;
    }
    LogInfo("Auth token set via environment variable");

    // Also write token file as fallback for the Python bridge
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        char tokenPath[MAX_PATH];
        snprintf(tokenPath, MAX_PATH, "%sx64dbg_mcp_token.txt", tempPath);

        // F-15: create the token file with an explicit DACL naming only the
        // current user, instead of relying on the process default DACL.
        SECURITY_ATTRIBUTES sa;
        PSECURITY_DESCRIPTOR sd = nullptr;
        bool haveSecurity = BuildCurrentUserOnlySecurity(sa, sd);
        if (!haveSecurity) {
            // Non-fatal: fall back to the default DACL (the previous
            // behaviour) rather than leaving the bridge with no token file.
            LogError("Could not build restrictive DACL for token file: %d "
                     "(falling back to default security)", GetLastError());
        }

        // A security descriptor passed to CreateFileA applies only when the
        // file is CREATED. With CREATE_ALWAYS an existing file is truncated
        // and KEEPS ITS OLD DACL, so a stale token file from an earlier run
        // (or one pre-created by someone else) would silently defeat the ACL
        // above. Remove it first; a failure here is only interesting if the
        // file actually exists.
        if (!DeleteFileA(tokenPath) && GetLastError() != ERROR_FILE_NOT_FOUND) {
            LogError("Could not remove stale token file before recreate: %d", GetLastError());
        }

        HANDLE hFile = CreateFileA(
            tokenPath,
            GENERIC_WRITE,
            FILE_SHARE_READ,
            haveSecurity ? &sa : nullptr,   // explicit user-only DACL
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        // The descriptor is consumed at creation time; the file keeps its ACL.
        if (sd) {
            LocalFree(sd);
            sd = nullptr;
        }

        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten;
            if (WriteFile(hFile, token, (DWORD)strlen(token), &bytesWritten, nullptr)) {
                LogInfo("Created auth token file: %s", tokenPath);
            } else {
                LogError("Failed to write token file: %d", GetLastError());
            }
            CloseHandle(hFile);
        } else {
            LogError("Failed to create auth token file: %d (non-fatal, env var is primary)", GetLastError());
        }
    }

    // Create shutdown event for graceful termination
    g_shutdownEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!g_shutdownEvent) {
        LogError("Failed to create shutdown event: %d", GetLastError());
        return;
    }

    // Create pipe-ready event (auto-reset, initially non-signaled)
    g_pipeReadyEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    if (!g_pipeReadyEvent) {
        LogError("Failed to create pipe-ready event: %d", GetLastError());
        CloseHandle(g_shutdownEvent);
        g_shutdownEvent = nullptr;
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
        CloseHandle(g_pipeReadyEvent);
        g_pipeReadyEvent = nullptr;
        CloseHandle(g_shutdownEvent);
        g_shutdownEvent = nullptr;
        return;
    }

    // Wait for pipe to be created (up to 5 seconds, replaces unreliable Sleep(100))
    DWORD waitResult = WaitForSingleObject(g_pipeReadyEvent, 5000);
    CloseHandle(g_pipeReadyEvent);
    g_pipeReadyEvent = nullptr;

    if (waitResult != WAIT_OBJECT_0) {
        LogError("Pipe creation timed out after 5 seconds");
        g_running = false;
        SetEvent(g_shutdownEvent);
        WaitForSingleObject(g_pipeThread, 1000);
        CloseHandle(g_pipeThread); g_pipeThread = nullptr;
        CloseHandle(g_shutdownEvent); g_shutdownEvent = nullptr;
        SetEnvironmentVariableA("OBSIDIAN_AUTH_TOKEN", nullptr);
        return;
    }

    // Spawn HTTP server process
    if (!SpawnHTTPServer()) {
        LogError("Failed to spawn HTTP server");
        g_running = false;
        SetEvent(g_shutdownEvent);
        WaitForSingleObject(g_pipeThread, 1000);
        CloseHandle(g_pipeThread); g_pipeThread = nullptr;
        CloseHandle(g_shutdownEvent); g_shutdownEvent = nullptr;
        SetEnvironmentVariableA("OBSIDIAN_AUTH_TOKEN", nullptr);
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
