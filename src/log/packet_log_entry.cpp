#include "log/packet_log_entry.hpp"

PacketLogEntry::PacketLogEntry(const char* src_ip, const char* dst_ip, const tcpheader* tcp)
    : src_ip_(src_ip), dst_ip_(dst_ip), tcp_(tcp) {}

std::string PacketLogEntry::format() const {
    std::ostringstream oss;
	
	oss << get_timestamp() 
        << src_ip_ << ":" << ntohs(tcp_->th_sport) << "->"
        << dst_ip_ << ":" << ntohs(tcp_->th_dport) << ",";
    if (tcp_->th_flags & TH_FIN) oss << "fin ";
    if (tcp_->th_flags & TH_SYN) oss << "syn ";
    if (tcp_->th_flags & TH_RST) oss << "rst ";
    if (tcp_->th_flags & TH_PUSH) oss << "psh ";
    if (tcp_->th_flags & TH_ACK) oss << "ack ";
    if (tcp_->th_flags & TH_URG) oss << "urg ";

    return oss.str();
}
