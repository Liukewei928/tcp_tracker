#ifndef PACKET_LOG_ENTRY_HPP
#define PACKET_LOG_ENTRY_HPP

#include "log/log_entry.hpp"
#include "tcp_def/ip_tcp_header.hpp"
#include "tcp/connection_key.hpp"

class PacketLogEntry : public LogEntry {
public:
    PacketLogEntry(const ConnectionKey& key, const tcpheader* tcp);
    std::string format() const override;

private:
    const tcpheader* tcp_;
};

#endif // PACKET_LOG_ENTRY_HPP
