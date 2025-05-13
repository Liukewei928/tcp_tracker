#ifndef LOG_MANAGER_HPP
#define LOG_MANAGER_HPP

#include "log/log.hpp"
#include <string>
#include <vector>
#include <memory>

class LogManager {
public:
    static LogManager& get_instance();

    LogManager(const LogManager&) = delete; // Prevent copying
    LogManager& operator=(const LogManager&) = delete;
    bool init(bool enable, bool truncate, const std::vector<std::string>& print_out_logs);
    Log& get_registered_log(const std::string& filename);

private:
    LogManager() = default;
    ~LogManager() = default;
    bool register_logs(bool enable, const std::vector<std::string>& print_out_logs);
    void truncate_all_logs();

    std::vector<Log> registered_logs_;
    Log dummy_log;
};

#endif // LOG_MANAGER_HPP
