#include "log/packet_log_entry.hpp"

PacketLogEntry::PacketLogEntry(const ConnectionKey& key, const tcpheader* tcp)
    : LogEntry(key), tcp_(tcp) {}

std::string PacketLogEntry::format() const {
    std::ostringstream oss;
	
	oss << get_timestamp() << get_direction();
    if (tcp_->th_flags & TH_FIN) oss << "fin ";
    if (tcp_->th_flags & TH_SYN) oss << "syn ";
    if (tcp_->th_flags & TH_RST) oss << "rst ";
    if (tcp_->th_flags & TH_PUSH) oss << "psh ";
    if (tcp_->th_flags & TH_ACK) oss << "ack ";
    if (tcp_->th_flags & TH_URG) oss << "urg ";

    return oss.str();
}
