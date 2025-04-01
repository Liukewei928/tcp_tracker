#ifndef LOG_HPP
#define LOG_HPP

#include "log/log_entry.hpp"
#include <string>
#include <fstream>
#include <vector>
#include <chrono>
#include <memory>
#include <mutex>

struct FlushPolicy {
    int max_updates = 1000;  // Flush after N updates
    int max_minutes = 5;     // Flush after N minutes
    size_t max_size = 10 * 1024 * 1024;  // 10 MB
};

class Log {
public:
    Log(const std::string& filename, bool enabled, const FlushPolicy& policy = FlushPolicy());
    ~Log();
    void log(const std::shared_ptr<LogEntry>& entry);
    void flush();
	void truncate();

private:
    void check_size_and_truncate();

    std::string filename_;
    bool enabled_;
    FlushPolicy policy_;
    std::ofstream file_;
    std::vector<std::shared_ptr<LogEntry>> buffer_;
    int update_count_;
    std::chrono::steady_clock::time_point last_flush_time_;
    std::mutex mutex_;
};

#endif // LOG_HPP
