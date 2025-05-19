#include "log/packet_log_entry.hpp"
#include <iostream>
#include <iomanip>

PacketLogEntry::PacketLogEntry(const ConnectionKey& key, const PacketKey& pkey)
    : LogEntry(key), pkey_(pkey) {
}

std::string PacketLogEntry::format() const {
    std::ostringstream oss;
    oss << get_timestamp() << get_direction();
    oss << "len:" << pkey_.total_len <<  "," << pkey_.payload_len << ",";

    // TCP
    oss << "tcp:"; 
    if (pkey_.tcp->th_flags & TH_FIN) oss << "fin ";
    if (pkey_.tcp->th_flags & TH_SYN) oss << "syn ";
    if (pkey_.tcp->th_flags & TH_RST) oss << "rst ";
    if (pkey_.tcp->th_flags & TH_PUSH) oss << "psh ";
    if (pkey_.tcp->th_flags & TH_ACK) oss << "ack ";
    if (pkey_.tcp->th_flags & TH_URG) oss << "urg ";

    // Payload
    if (pkey_.payload_len) oss << std::endl;
    oss << get_formatted_buffer(pkey_.payload, pkey_.payload_len);
    return oss.str();
}

