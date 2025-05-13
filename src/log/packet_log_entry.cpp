#include "log/packet_log_entry.hpp"
#include <iostream>
#include <iomanip>

PacketLogEntry::PacketLogEntry(const ConnectionKey& key, const tcpheader* tcp, const u_char* packet, 
     size_t packet_len)
    : LogEntry(key), tcp_(tcp), packet_(packet), packet_len_(packet_len) {}

std::string PacketLogEntry::format() const {
    std::ostringstream oss;
    
	oss << get_timestamp() << get_direction();
    oss << "Len:" << std::dec << packet_len_ << std::endl;
    for (size_t i = 0; i < std::min(packet_len_, size_t(64)); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet_[i]) << " ";
    }
    oss << std::endl;

    oss << "TCP: ";
    if (tcp_->th_flags & TH_FIN) oss << "fin ";
    if (tcp_->th_flags & TH_SYN) oss << "syn ";
    if (tcp_->th_flags & TH_RST) oss << "rst ";
    if (tcp_->th_flags & TH_PUSH) oss << "psh ";
    if (tcp_->th_flags & TH_ACK) oss << "ack ";
    if (tcp_->th_flags & TH_URG) oss << "urg ";

    return oss.str();
}
