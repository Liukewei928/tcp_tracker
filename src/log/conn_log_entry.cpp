#include "log/conn_log_entry.hpp"

ConnLogEntry::ConnLogEntry(const ConnectionKey& key, const std::string& ss)
    : LogEntry(key), content_(ss) {}

std::string ConnLogEntry::format() const {
    std::ostringstream oss;
	oss << get_timestamp() << get_direction() << content_;
    return oss.str();
}
