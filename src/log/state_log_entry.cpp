#include "log/state_log_entry.hpp"

StateLogEntry::StateLogEntry(const ConnectionKey& key, const std::string& state)
    : LogEntry(key), state_(state) {}

std::string StateLogEntry::format() const {
    std::ostringstream oss;
	oss << get_timestamp() << get_direction() << state_;
    return oss.str();
}
