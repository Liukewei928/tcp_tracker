#ifndef LOG_ENTRY_HPP
#define LOG_ENTRY_HPP

#include "conn/connection_key.hpp"
#include <sstream>
#include <string>
#include <chrono>

class LogEntry {
public:
    LogEntry();
	LogEntry(const ConnectionKey& key);
	virtual ~LogEntry() = default;
    virtual std::string format() const = 0;
    static std::string get_formatted_buffer(const uint8_t* buf, const size_t len);

protected:
	std::string get_timestamp() const;
    std::string get_direction() const;
    
private:
	int utc_offset_ {0};	
    std::chrono::system_clock::time_point timestamp_;
    const ConnectionKey key_;
};

#endif // LOG_ENTRY_HPP
