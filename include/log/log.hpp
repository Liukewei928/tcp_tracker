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
    Log(const Log&) = delete;
    Log& operator=(const Log&) = delete;

    // Enable move semantics for C++ STL 
    Log(Log&& other) noexcept; 
    Log& operator=(Log&& other) noexcept;
    Log() = default;
    Log(const std::string& filename, bool enabled = false, bool print_out = false,
        const FlushPolicy& policy = FlushPolicy());
    ~Log();
    bool operator==(const std::string& rhs) const;

    void log(const std::shared_ptr<LogEntry>& entry);
    void flush();
	void truncate();
    const std::string& get_filename() {
        return filename_;
    };

private:
    void check_size_and_truncate();

    std::string filename_;
    bool enabled_;
    bool print_out_;
    FlushPolicy policy_;
    std::ofstream file_;
    std::vector<std::shared_ptr<LogEntry>> buffer_;
    int update_count_;
    std::chrono::steady_clock::time_point last_flush_time_;
    std::mutex mutex_;
};

#endif // LOG_HPP
