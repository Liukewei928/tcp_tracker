#include "log/log_entries.hpp"
#include <sstream>
#include <iomanip>

PacketLogEntry::PacketLogEntry(const struct pcap_pkthdr* header, const char* src_ip, const char* dst_ip, const tcpheader* tcp)
    : header_(header), src_ip_(src_ip), dst_ip_(dst_ip), tcp_(tcp) {}

std::string PacketLogEntry::format() const {
    std::ostringstream oss;
    auto time_t = header_->ts.tv_sec;
    oss << "[" << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S.")
        << std::setfill('0') << std::setw(6) << header_->ts.tv_usec << " UTC] tcp_packet:\n"
        << "src: " << src_ip_ << ":" << ntohs(tcp_->th_sport) << "\n"
        << "dst: " << dst_ip_ << ":" << ntohs(tcp_->th_dport) << "\n"
        << "flags: ";
    if (tcp_->th_flags & TH_FIN) oss << "fin ";
    if (tcp_->th_flags & TH_SYN) oss << "syn ";
    if (tcp_->th_flags & TH_RST) oss << "rst ";
    if (tcp_->th_flags & TH_PUSH) oss << "psh ";
    if (tcp_->th_flags & TH_ACK) oss << "ack ";
    if (tcp_->th_flags & TH_URG) oss << "urg ";
    oss << "\n";
    return oss.str();
}

std::chrono::system_clock::time_point PacketLogEntry::timestamp() const {
    return std::chrono::system_clock::from_time_t(header_->ts.tv_sec) +
           std::chrono::microseconds(header_->ts.tv_usec);
}

StateLogEntry::StateLogEntry(const ConnectionKey& key, const std::string& state, std::chrono::steady_clock::time_point now)
    : key_(key), state_(state), timestamp_(std::chrono::system_clock::now()) {}

std::string StateLogEntry::format() const {
    std::ostringstream oss;
    auto time_t_val = std::chrono::system_clock::to_time_t(timestamp_);
    oss << "[" << std::put_time(std::gmtime(&time_t_val), "%Y-%m-%d %H:%M:%S.")
        << std::setfill('0') << std::setw(6)
        << std::chrono::duration_cast<std::chrono::microseconds>(timestamp_.time_since_epoch()).count() % 1000000
        << " UTC] " << key_.src_ip << ":" << key_.src_port << " -> " << key_.dst_ip << ":" << key_.dst_port << " "
        << state_;
    return oss.str();
}

std::chrono::system_clock::time_point StateLogEntry::timestamp() const {
    return timestamp_;
}

L7ProtocolLogEntry::L7ProtocolLogEntry(const std::string& protocol, const std::string& details)
    : protocol_(protocol), details_(details), timestamp_(std::chrono::system_clock::now()) {}

std::string L7ProtocolLogEntry::format() const {
    std::ostringstream oss;
    auto time_t_val = std::chrono::system_clock::to_time_t(timestamp_);
    oss << "[" << std::put_time(std::gmtime(&time_t_val), "%Y-%m-%d %H:%M:%S.")
        << std::setfill('0') << std::setw(6)
        << std::chrono::duration_cast<std::chrono::microseconds>(timestamp_.time_since_epoch()).count() % 1000000
        << " UTC] " << protocol_ << ": " << details_;
    return oss.str();
}

std::chrono::system_clock::time_point L7ProtocolLogEntry::timestamp() const {
    return timestamp_;
}
