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
    for (size_t i = 0; i < std::min(pkey_.payload_len, size_t(128)); ++i) {
        if (i > 0 && i % 32 == 0) oss << std::endl;
        else if (i > 0 && i % 16 == 0) oss << " ";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pkey_.payload[i]) << " ";
    }

    return oss.str();
}
