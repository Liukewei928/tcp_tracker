#include "log/log_manager.hpp"
#include <algorithm>
#include <iostream>

std::vector<std::string> to_register_logs = {
    "packet", "tcp", "reassm", "reassm_data", "tls"
};

LogManager& LogManager::get_instance() {
    static LogManager instance;
    return instance;
}

bool LogManager::init(bool enable, bool truncate, const std::vector<std::string>& print_out_logs) {
    if (!register_logs(enable, print_out_logs)) {
        return false;
    }

    if (truncate) {
        truncate_all_logs();
    }
    
    return true;
}

bool LogManager::register_logs(bool enable, const std::vector<std::string>& print_out_logs) {
    for (const auto& to_add : print_out_logs) {
        if (std::find(to_register_logs.begin(), to_register_logs.end(), to_add)
            != to_register_logs.end()) {
            std::string filename = to_add + ".log";
            Log log(filename, enable, true);
            registered_logs_.push_back(std::move(log));
            
            auto added = std::remove(to_register_logs.begin(), to_register_logs.end(), to_add);
            to_register_logs.erase(added, to_register_logs.end());
        } else {
            std::cerr << "Failed to register log: " << to_add << std::endl;
            return false;
        }
    }

    for (const auto& to_add : to_register_logs) {
        std::string filename = to_add + ".log";
        Log log(filename, enable, false);
        registered_logs_.push_back(std::move(log));
    }
    
    return true;
}

void LogManager::truncate_all_logs() {
    std::cout << "Truncating logs..." << std::endl;
    for (auto& log : registered_logs_) {
        std::cout << log.get_filename() << std::endl;
        log.truncate();
    }
}

Log& LogManager::get_registered_log(const std::string& filename) {
    auto log = std::find(registered_logs_.begin(), registered_logs_.end(), filename);
    if (log != registered_logs_.end()) {
        return *log;
    }

    return dummy_log;
}
