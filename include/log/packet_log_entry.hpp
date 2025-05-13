#ifndef PACKET_LOG_ENTRY_HPP
#define PACKET_LOG_ENTRY_HPP

#include "log/log_entry.hpp"
#include "definations/ip_tcp_header.hpp"
#include "conn/connection_key.hpp"

class PacketLogEntry : public LogEntry {
public:
    PacketLogEntry(const ConnectionKey& key, const tcpheader* tcp, const u_char* packet,  size_t packet_len);
    std::string format() const override;

private:
    const tcpheader* tcp_;
    const u_char* packet_;
    size_t packet_len_;
};

#endif // PACKET_LOG_ENTRY_HPP
