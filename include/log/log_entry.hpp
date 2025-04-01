#ifndef LOG_ENTRY_HPP
#define LOG_ENTRY_HPP

#include <sstream>
#include <string>
#include <chrono>
#include <ctime>

class UTCOffset {
public:
    static UTCOffset* get_instance() {
        if (!instance_)
            instance_ = new UTCOffset();
        return instance_;
    }

    int get_offset() const { return offset_; }

private:
    static UTCOffset* instance_;
    int offset_;  // Offset in hours
    UTCOffset() {
        time_t now = time(nullptr);
        struct tm* gmTime = gmtime(&now);
        struct tm* localTime = localtime(&now);
        offset_ = difftime(mktime(localTime), mktime(gmTime)) / 3600;
    }
};

class LogEntry {
public:
	LogEntry();
	virtual ~LogEntry() = default;
    virtual std::string format() const = 0;

protected:
	std::string get_timestamp() const;

private:
	int utc_offset_ {0};	
    std::chrono::system_clock::time_point timestamp_;
};

#endif // LOG_ENTRY_HPP
