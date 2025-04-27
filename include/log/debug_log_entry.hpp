#ifndef DEBUG_LOG_ENTRY_HPP
#define DEBUG_LOG_ENTRY_HPP

#include "log/log_entry.hpp"
#include <string>

class DebugLogEntry : public LogEntry {
public:
    explicit DebugLogEntry(const std::string& message);
    std::string format() const override;

private:
    std::string message_;
};

#endif // DEBUG_LOG_ENTRY_HPP 