#include "event_system.h"
#include <sstream>
#include <iomanip>
#include <chrono>

// Get current time in milliseconds
static uint64_t GetCurrentTimeMs() {
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return static_cast<uint64_t>(ms.count());
}

// JSON escape helper
//
// AUDIT (JSON escaping / non-ASCII): this is the second copy of the escaper --
// plugin.cpp has JsonEscape -- and it had the same defect: bytes >= 0x80 were
// copied through raw.
//
// It matters more here than anywhere else, because the strings this function
// sees are the ones the debuggee supplies most directly: module paths from
// LOADDLL/UNLOADDLL callbacks, breakpoint names, and OutputDebugString content
// the sample chooses byte for byte. A single high byte in any of them makes the
// /api/events response invalid UTF-8, and the Python bridge's response.json()
// raises on it -- so the sample can permanently break event polling for the
// analysis session by calling OutputDebugStringA("\xff").
//
// Escape every byte outside printable ASCII (0x20..0x7E) as \u00XX. That is a
// latin-1 reading of the byte -- a guess about encoding, but a reversible one
// that always decodes. \b and \f are added for parity with plugin.cpp's copy;
// they were previously only reachable via the generic \u path.
static std::string JsonEscapeEvent(const std::string& str) {
    std::string result;
    result.reserve(str.length() * 2);
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

// Convert event type to string
const char* EventTypeToString(DebugEventType type) {
    switch (type) {
        case DebugEventType::BREAKPOINT_HIT: return "breakpoint_hit";
        case DebugEventType::EXCEPTION: return "exception";
        case DebugEventType::PAUSED: return "paused";
        case DebugEventType::RUNNING: return "running";
        case DebugEventType::STEPPED: return "stepped";
        case DebugEventType::PROCESS_STARTED: return "process_started";
        case DebugEventType::PROCESS_EXITED: return "process_exited";
        case DebugEventType::THREAD_CREATED: return "thread_created";
        case DebugEventType::THREAD_EXITED: return "thread_exited";
        case DebugEventType::MODULE_LOADED: return "module_loaded";
        case DebugEventType::MODULE_UNLOADED: return "module_unloaded";
        case DebugEventType::DEBUG_STRING: return "debug_string";
        case DebugEventType::SYSTEM_BREAKPOINT: return "system_breakpoint";
        default: return "unknown";
    }
}

// Convert string to event type
DebugEventType StringToEventType(const std::string& str) {
    if (str == "breakpoint_hit") return DebugEventType::BREAKPOINT_HIT;
    if (str == "exception") return DebugEventType::EXCEPTION;
    if (str == "paused") return DebugEventType::PAUSED;
    if (str == "running") return DebugEventType::RUNNING;
    if (str == "stepped") return DebugEventType::STEPPED;
    if (str == "process_started") return DebugEventType::PROCESS_STARTED;
    if (str == "process_exited") return DebugEventType::PROCESS_EXITED;
    if (str == "thread_created") return DebugEventType::THREAD_CREATED;
    if (str == "thread_exited") return DebugEventType::THREAD_EXITED;
    if (str == "module_loaded") return DebugEventType::MODULE_LOADED;
    if (str == "module_unloaded") return DebugEventType::MODULE_UNLOADED;
    if (str == "debug_string") return DebugEventType::DEBUG_STRING;
    if (str == "system_breakpoint") return DebugEventType::SYSTEM_BREAKPOINT;
    return DebugEventType::UNKNOWN;
}

// DebugEvent::ToJson implementation
std::string DebugEvent::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"id\":" << id << ",";
    ss << "\"type\":\"" << EventTypeToString(type) << "\",";
    ss << "\"timestamp\":" << timestamp << ",";
    ss << "\"address\":\"" << std::hex << address << std::dec << "\",";
    ss << "\"thread_id\":" << threadId << ",";
    ss << "\"module\":\"" << JsonEscapeEvent(module) << "\"";
    if (!details.empty()) {
        ss << ",\"details\":\"" << JsonEscapeEvent(details) << "\"";
    }
    ss << "}";
    return ss.str();
}

// EventQueue implementation
EventQueue& EventQueue::Instance() {
    static EventQueue instance;
    return instance;
}

EventQueue::EventQueue() : m_startTime(GetCurrentTimeMs()) {
}

void EventQueue::PushEvent(DebugEventType type, uint64_t address,
                           uint32_t threadId, const std::string& module,
                           const std::string& details) {
    if (!m_enabled) return;

    std::lock_guard<std::mutex> lock(m_mutex);

    // Create event
    DebugEvent event;
    event.id = m_nextEventId++;
    event.type = type;
    event.timestamp = GetCurrentTimeMs() - m_startTime;
    event.address = address;
    event.threadId = threadId;
    event.module = module;
    event.details = details;

    // Add to queue
    m_events.push_back(std::move(event));

    // Trim queue if too large (remove oldest events)
    if (m_events.size() > MAX_QUEUE_SIZE) {
        m_events.erase(m_events.begin(), m_events.begin() + (m_events.size() - MAX_QUEUE_SIZE));
    }
}

std::string EventQueue::PopEvents(size_t maxEvents) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::stringstream ss;
    ss << "[";

    size_t count = std::min(maxEvents, m_events.size());
    for (size_t i = 0; i < count; i++) {
        if (i > 0) ss << ",";
        ss << m_events[i].ToJson();
    }
    ss << "]";

    // Remove returned events
    if (count > 0) {
        m_events.erase(m_events.begin(), m_events.begin() + count);
    }

    return ss.str();
}

std::string EventQueue::PeekEvents(size_t maxEvents) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::stringstream ss;
    ss << "[";

    size_t count = std::min(maxEvents, m_events.size());
    for (size_t i = 0; i < count; i++) {
        if (i > 0) ss << ",";
        ss << m_events[i].ToJson();
    }
    ss << "]";

    return ss.str();
}

void EventQueue::Clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events.clear();
}

size_t EventQueue::Size() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_events.size();
}
