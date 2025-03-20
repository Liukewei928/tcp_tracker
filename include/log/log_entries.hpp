#ifndef LOG_ENTRIES_HPP
#define LOG_ENTRIES_HPP

#include "log/log.hpp"
#include "tcp/connection.hpp"
#include "tcp/ip_tcp_header.hpp"
#include <pcap.h>
#include <string>
#include <chrono>

class PacketLogEntry : public LogEntry {
public:
    PacketLogEntry(const struct pcap_pkthdr* header, const char* src_ip, const char* dst_ip, const tcpheader* tcp);
    std::string format() const override;
    std::chrono::system_clock::time_point timestamp() const override;

private:
    const struct pcap_pkthdr* header_;
    std::string src_ip_;
    std::string dst_ip_;
    const tcpheader* tcp_;
};

class StateLogEntry : public LogEntry {
public:
    StateLogEntry(const ConnectionKey& key, const std::string& state, std::chrono::steady_clock::time_point now);
    std::string format() const override;
    std::chrono::system_clock::time_point timestamp() const override;

private:
    ConnectionKey key_;
    std::string state_;
    std::chrono::system_clock::time_point timestamp_;
};

class L7ProtocolLogEntry : public LogEntry {
public:
    L7ProtocolLogEntry(const std::string& protocol, const std::string& details);
    std::string format() const override;
    std::chrono::system_clock::time_point timestamp() const override;

private:
    std::string protocol_;
    std::string details_;
    std::chrono::system_clock::time_point timestamp_;
};

#endif // LOG_ENTRIES_HPP
