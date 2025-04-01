#ifndef PACKET_LOG_ENTRY_HPP
#define PACKET_LOG_ENTRY_HPP

#include "log/log_entry.hpp"
#include "tcp/ip_tcp_header.hpp"

class PacketLogEntry : public LogEntry {
public:
    PacketLogEntry(const char* src_ip, const char* dst_ip, const tcpheader* tcp);
    std::string format() const override;

private:
    std::string src_ip_;
    std::string dst_ip_;
    const tcpheader* tcp_;
};

#endif // PACKET_LOG_ENTRY_HPP
