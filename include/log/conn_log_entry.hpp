#ifndef CONN_LOG_ENTRY_HPP
#define CONN_LOG_ENTRY_HPP

#include "log/log_entry.hpp"
#include "conn/connection.hpp"

class ConnLogEntry : public LogEntry {
public:
    ConnLogEntry(const ConnectionKey& key, const std::string& state);
    std::string format() const override;

private:
    std::string content_;
};

#endif // CONN_LOG_ENTRY_HPP 
