#include "conn/packet_processor.hpp"
#include "log/packet_log_entry.hpp"
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <chrono>
#include <iostream>

PacketProcessor::PacketProcessor(ConnectionManager& connection_manager)
    : connection_manager_(connection_manager) {
}

PacketProcessor::~PacketProcessor() {
    packet_log_.flush();
}

bool PacketProcessor::validate_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    if (header->caplen < 54) return false;

    const auto* ip = reinterpret_cast<const IPHeader*>(packet + 14);
    return ip->iph_protocol == IPPROTO_TCP;
}

bool PacketProcessor::extract_packet(const u_char* packet, const size_t packet_len, 
    ConnectionKey& key, PacketKey& pkey) {
    pkey.ip = const_cast<IPHeader*>(reinterpret_cast<const IPHeader*>(packet + 14));
    pkey.iph_len = pkey.ip->iph_ihl * 4;
    if (pkey.iph_len < 20) {
        pkey.tcp = nullptr;
        return false;
    }

    pkey.tcp = const_cast<TCPHeader*>(reinterpret_cast<const TCPHeader*>(packet + 14 + pkey.iph_len));
    pkey.tcph_len = pkey.tcp->th_off * 4;
    pkey.payload = const_cast<uint8_t*>(packet + 14 + pkey.iph_len + pkey.tcph_len);
    pkey.payload_len = ntohs(pkey.ip->iph_len) - pkey.iph_len - pkey.tcph_len;
    pkey.total_len = 14 + pkey.iph_len + pkey.tcph_len + pkey.payload_len;
    if (packet_len != pkey.total_len)
    {
        return false;
    }
    
    char src_ip[INET_ADDRSTRLEN] = {0}, dst_ip[INET_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET, &(pkey.ip->iph_source), src_ip, INET_ADDRSTRLEN) ||
        !inet_ntop(AF_INET, &(pkey.ip->iph_dest), dst_ip, INET_ADDRSTRLEN)) {
        pkey.tcp = nullptr;
        return false;
    }

    key = ConnectionKey(src_ip, ntohs(pkey.tcp->th_sport), dst_ip, ntohs(pkey.tcp->th_dport));
    return true;
}

void PacketProcessor::handle_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    if (!validate_packet(header, packet)) return;

    ConnectionKey key;
    PacketKey pkey;
    if (!extract_packet(packet, header->len, key, pkey)) return;

    packet_log_.log(std::make_shared<PacketLogEntry>(key, pkey));
    connection_manager_.process_packet(key, pkey);
}

void packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    if (!user) return;
    auto* handler = reinterpret_cast<PacketProcessor*>(user);
    handler->handle_packet(header, packet);
}
