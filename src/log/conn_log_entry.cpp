#include "log/conn_log_entry.hpp"

ConnLogEntry::ConnLogEntry(const ConnectionKey& key, const std::string& content)
    : LogEntry(key), content_(content) {}

std::string ConnLogEntry::format() const {
    std::ostringstream oss;
	oss << get_timestamp() << get_direction() << content_;
    return oss.str();
}
