#include "log/state_log_entry.hpp"

StateLogEntry::StateLogEntry(const ConnectionKey& key, const std::string& state)
    : key_(key), state_(state) {}

std::string StateLogEntry::format() const {
    std::ostringstream oss;
	oss << get_timestamp() 
		<< key_.src_ip << ":" << key_.src_port << " -> " << key_.dst_ip << ":" << key_.dst_port << " "
        << state_;
	printf("%s\n", oss.str().c_str());
    return oss.str();
}
