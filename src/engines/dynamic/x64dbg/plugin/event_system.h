#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>

// Event types for debug events
enum class DebugEventType {
    // Execution events
    BREAKPOINT_HIT = 1,
    EXCEPTION = 2,
    PAUSED = 3,
    RUNNING = 4,
    STEPPED = 5,

    // Process/Thread events
    PROCESS_STARTED = 10,
    PROCESS_EXITED = 11,
    THREAD_CREATED = 12,
    THREAD_EXITED = 13,

    // Module events
    MODULE_LOADED = 20,
    MODULE_UNLOADED = 21,

    // Debug events
    DEBUG_STRING = 30,
    SYSTEM_BREAKPOINT = 31,

    // Internal
    UNKNOWN = 0
};

// Single debug event structure
struct DebugEvent {
    uint64_t id;                  // Unique event ID
    DebugEventType type;          // Event type
    uint64_t timestamp;           // Event timestamp (ms since plugin start)
    uint64_t address;             // Address (if applicable)
    uint32_t threadId;            // Thread ID (if applicable)
    std::string module;           // Module name (if applicable)
    std::string details;          // Additional details (JSON or text)

    // Convert to JSON string
    std::string ToJson() const;
};

// Event queue manager
class EventQueue {
public:
    static EventQueue& Instance();

    // Add event to queue
    void PushEvent(DebugEventType type, uint64_t address = 0,
                   uint32_t threadId = 0, const std::string& module = "",
                   const std::string& details = "");

    // Get events since last poll (returns JSON array)
    std::string PopEvents(size_t maxEvents = 100);

    // Get events without removing (peek)
    std::string PeekEvents(size_t maxEvents = 100) const;

    // Clear all events
    void Clear();

    // Get queue size
    size_t Size() const;

    // Get next event ID (for filtering)
    uint64_t GetNextEventId() const { return m_nextEventId.load(); }

    // Enable/disable event collection
    void SetEnabled(bool enabled) { m_enabled = enabled; }
    bool IsEnabled() const { return m_enabled; }

private:
    EventQueue();
    ~EventQueue() = default;

    // Non-copyable
    EventQueue(const EventQueue&) = delete;
    EventQueue& operator=(const EventQueue&) = delete;

    mutable std::mutex m_mutex;
    std::vector<DebugEvent> m_events;
    std::atomic<uint64_t> m_nextEventId{1};
    std::atomic<bool> m_enabled{true};
    uint64_t m_startTime;

    // Max events to keep in queue
    static constexpr size_t MAX_QUEUE_SIZE = 1000;
};

// Helper to convert event type to string
const char* EventTypeToString(DebugEventType type);

// Helper to convert string to event type
DebugEventType StringToEventType(const std::string& str);
