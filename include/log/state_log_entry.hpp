#ifndef STATE_LOG_ENTRY_HPP
#define STATE_LOG_ENTRY_HPP

#include "log/log_entry.hpp"
#include "tcp/connection.hpp"

class StateLogEntry : public LogEntry {
public:
    StateLogEntry(const ConnectionKey& key, const std::string& state);
    std::string format() const override;

private:
    ConnectionKey key_;
    std::string state_;
};

#endif // STATE_LOG_ENTRY_HPP 
