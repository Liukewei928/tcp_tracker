#include "log/log_entry.hpp"
#include "misc/utc_offset.hpp"
#include <iomanip>

UTCOffset* UTCOffset::instance_ = nullptr;

LogEntry::LogEntry()
    : utc_offset_(UTCOffset::get_instance()->get_offset()), timestamp_(std::chrono::system_clock::now()) {}

LogEntry::LogEntry(const ConnectionKey& key)
    : key_(key), utc_offset_(UTCOffset::get_instance()->get_offset()), timestamp_(std::chrono::system_clock::now()) {}

std::string LogEntry::get_timestamp() const {
    std::ostringstream oss;
	auto time_t_val = std::chrono::system_clock::to_time_t(timestamp_);
    oss << "[" << std::put_time(std::gmtime(&time_t_val), "%Y-%m-%d %H:%M:%S.")
        << std::setfill('0') << std::setw(6) 
        << std::chrono::duration_cast<std::chrono::microseconds>(timestamp_.time_since_epoch()).count() % 1000000
		<< " " << (utc_offset_ >= 0 ? "+" : "") << utc_offset_  << "]";

	return oss.str();
}

std::string LogEntry::get_direction() const {
    std::ostringstream oss;
    oss << key_.src_ip << ":" << key_.src_port << "->" << key_.dst_ip << ":" << key_.dst_port << ",";
    return oss.str();
}

std::string LogEntry::get_formatted_buffer(const uint8_t* buf, const size_t len) {
    std::ostringstream oss;
    size_t print_len = std::min(len, size_t(128));

    for (size_t i = 0; i < print_len; ++i) {
        if (i > 0 && i % 32 == 0) oss << std::endl;
        else if (i > 0 && i % 16 == 0) oss << "  ";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]) << " ";
    }

    if (len > 128) {
        oss << "\n... ";
        size_t start = len - 16;
        for (size_t i = start; i < len; ++i) {
            if ((i - start) > 0 && (i - start) % 16 == 0) oss << std::endl;
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]) << " ";
        }
    }

    return oss.str();
}