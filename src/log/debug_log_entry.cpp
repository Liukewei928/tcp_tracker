#include "log/debug_log_entry.hpp"

DebugLogEntry::DebugLogEntry(const std::string& message)
    : LogEntry(), message_(message) {
}

std::string DebugLogEntry::format() const {
    return get_timestamp() + " [DEBUG] " + message_;
} 