#pragma once

// JSONL activity log for obsidian_server.
//
// WHY THIS EXISTS: the server's only diagnostic was obsidian_server.log, a
// plain-text file opened with fopen(..., "w") -- truncated on every start. The
// run that just crashed is exactly the run whose log you want, and it was gone
// the moment the server came back up. There were also no timestamps, so server
// events could not be lined up against anything client-side, and no way to tie
// an error line to the request that produced it.
//
// This writes one JSON object per line instead of a single JSON document. A
// document has to be closed to parse; if the server dies mid-write -- again,
// the case that matters -- you get an unterminated file and a parse error.
// JSONL stays valid up to the last complete line, appends without rewriting,
// and greps.
//
// WHAT IT DELIBERATELY DOES NOT RECORD: request and response bodies. A body
// here carries debuggee memory, module paths chosen by the sample, and
// analysed-sample paths -- the same content the F-10 remediation keeps out of
// model context, which has no business sitting in plaintext on disk either.
// Set OBSIDIAN_LOG_BODIES=1 to capture them anyway; that is a deliberate act
// for a debugging session, not the default.
//
// Single-threaded by design: the server handles one connection at a time in
// its accept loop, so there is no lock here. If that ever changes, this needs
// one.

#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace ActivityLog {

// Keep this many per-run logs. A crash must not cost you the previous run's
// file, so each start gets its own; without pruning the folder grows forever.
static const size_t MAX_LOG_FILES = 10;

// Stop writing past this size rather than filling the disk: a long trace
// session can produce events far faster than anyone will read them.
static const long long MAX_LOG_BYTES = 16LL * 1024 * 1024;

namespace detail {

inline FILE*& File() {
    static FILE* file = nullptr;
    return file;
}

inline long long& BytesWritten() {
    static long long written = 0;
    return written;
}

inline bool& Truncated() {
    static bool truncated = false;
    return truncated;
}

inline unsigned long long& RequestCounter() {
    static unsigned long long counter = 0;
    return counter;
}

// ISO 8601 UTC with milliseconds, so server events can be correlated with
// client-side timestamps without guessing a timezone.
inline std::string Timestamp() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buffer[64];
    snprintf(buffer, sizeof(buffer),
             "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return std::string(buffer);
}

inline std::string Escape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (size_t i = 0; i < value.size(); i++) {
        unsigned char c = static_cast<unsigned char>(value[i]);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char esc[8];
                    snprintf(esc, sizeof(esc), "\\u%04x", c);
                    out += esc;
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}

inline void WriteLine(const std::string& line) {
    FILE* file = File();
    if (!file || Truncated()) {
        return;
    }
    if (BytesWritten() >= MAX_LOG_BYTES) {
        Truncated() = true;
        fprintf(file,
                "{\"ts\":\"%s\",\"ev\":\"log.truncated\","
                "\"reason\":\"size cap reached\",\"limit_bytes\":%lld}\n",
                Timestamp().c_str(), MAX_LOG_BYTES);
        fflush(file);
        return;
    }
    BytesWritten() += static_cast<long long>(line.size()) + 1;
    fprintf(file, "%s\n", line.c_str());
    // Flushed per line: an unflushed buffer is lost in exactly the crash this
    // log exists to explain.
    fflush(file);
}

// Delete oldest files beyond the retention limit. Names embed a sortable
// timestamp, so lexicographic order is chronological order.
inline void Prune(const std::string& logDir, size_t keep) {
    std::vector<std::string> found;
    std::string pattern = logDir + "obsidian-*.jsonl";

    WIN32_FIND_DATAA findData;
    HANDLE handle = FindFirstFileA(pattern.c_str(), &findData);
    if (handle == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            found.push_back(std::string(findData.cFileName));
        }
    } while (FindNextFileA(handle, &findData));
    FindClose(handle);

    if (found.size() <= keep) {
        return;
    }
    std::sort(found.begin(), found.end());
    size_t removeCount = found.size() - keep;
    for (size_t i = 0; i < removeCount; i++) {
        std::string victim = logDir + found[i];
        DeleteFileA(victim.c_str());
    }
}

}  // namespace detail

// True when the operator has explicitly opted into body capture.
inline bool BodiesEnabled() {
    const char* value = getenv("OBSIDIAN_LOG_BODIES");
    return value != nullptr && value[0] == '1' && value[1] == '\0';
}

// One JSON object, built field by field and written when it goes out of scope.
// Writing on destruction means a call site cannot forget to emit.
class Event {
public:
    explicit Event(const char* name) {
        line_ = "{\"ts\":\"" + detail::Timestamp() + "\",\"ev\":\"";
        line_ += detail::Escape(name);
        line_ += "\"";
    }

    Event& Str(const char* key, const std::string& value) {
        line_ += ",\"";
        line_ += detail::Escape(key);
        line_ += "\":\"";
        line_ += detail::Escape(value);
        line_ += "\"";
        return *this;
    }

    Event& Num(const char* key, long long value) {
        char buffer[32];
        snprintf(buffer, sizeof(buffer), "%lld", value);
        line_ += ",\"";
        line_ += detail::Escape(key);
        line_ += "\":";
        line_ += buffer;
        return *this;
    }

    Event& Bool(const char* key, bool value) {
        line_ += ",\"";
        line_ += detail::Escape(key);
        line_ += "\":";
        line_ += (value ? "true" : "false");
        return *this;
    }

    // Bodies are the one field that can carry sample-controlled text, so this
    // is a no-op unless OBSIDIAN_LOG_BODIES=1 is set.
    Event& Body(const char* key, const std::string& value) {
        if (BodiesEnabled()) {
            Str(key, value);
        }
        return *this;
    }

    ~Event() {
        line_ += "}";
        detail::WriteLine(line_);
    }

private:
    std::string line_;

    Event(const Event&);
    Event& operator=(const Event&);
};

// Monotonic id tying request.received, the pipe events and request.completed
// together. Without it a failure cannot be attributed to a specific request.
inline unsigned long long NextRequestId() {
    return ++detail::RequestCounter();
}

// Millisecond clock for durations. GetTickCount64 rather than the CRT clock:
// no deprecation warnings, and monotonic across a wall-clock change.
inline unsigned long long NowMs() {
    return GetTickCount64();
}

// Open a new per-run log beside the executable. exeDir must end in a slash.
inline bool Init(const std::string& exeDir, const char* version, int port) {
    std::string logDir = exeDir + "logs\\";
    if (!CreateDirectoryA(logDir.c_str(), nullptr)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            return false;
        }
    }

    // Prune to one below the limit so this run's file brings it back to it.
    detail::Prune(logDir, MAX_LOG_FILES > 0 ? MAX_LOG_FILES - 1 : 0);

    SYSTEMTIME st;
    GetLocalTime(&st);
    DWORD pid = GetCurrentProcessId();

    char name[128];
    snprintf(name, sizeof(name),
             "obsidian-%04u%02u%02u-%02u%02u%02u-%lu.jsonl",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond,
             static_cast<unsigned long>(pid));

    std::string path = logDir + name;
    detail::File() = fopen(path.c_str(), "w");
    if (!detail::File()) {
        return false;
    }

    Event("server.start")
        .Str("version", version)
        .Num("pid", static_cast<long long>(pid))
        .Num("port", port)
        .Bool("bodies_logged", BodiesEnabled());
    return true;
}

// Final event and close. Safe to call when Init failed.
inline void Shutdown(bool ok, const char* reason) {
    if (!detail::File()) {
        return;
    }
    {
        Event("server.stop")
            .Bool("ok", ok)
            .Str("reason", reason)
            .Num("requests", static_cast<long long>(detail::RequestCounter()));
    }
    fclose(detail::File());
    detail::File() = nullptr;
}

// Path of nothing -- exposed so the text log can point a reader at the JSONL.
inline bool Active() {
    return detail::File() != nullptr;
}

}  // namespace ActivityLog
