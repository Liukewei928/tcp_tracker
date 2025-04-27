#include "conn/packet_processor.hpp"
#include "log/packet_log_entry.hpp"
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <chrono>
#include <iostream>

PacketProcessor::PacketProcessor(ConnectionManager& connection_manager, bool debug_mode)
    : connection_manager_(connection_manager)
    , packet_log_("packet.log", debug_mode)
{}

PacketProcessor::~PacketProcessor() {
    packet_log_.flush();
}

bool PacketProcessor::validate_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    if (header->caplen < 54) return false;

    const auto* ip = reinterpret_cast<const ipheader*>(packet + 14);
    return ip->iph_protocol == IPPROTO_TCP;
}

void PacketProcessor::extract_packet_info(const u_char* packet, ConnectionKey& key, const tcpheader*& tcp) {
    const auto* ip = reinterpret_cast<const ipheader*>(packet + 14);
    int ip_header_len = ip->iph_ihl * 4;
    if (ip_header_len < 20) {
        tcp = nullptr;
        return;
    }

    tcp = reinterpret_cast<const tcpheader*>(packet + 14 + ip_header_len);

    char src_ip[INET_ADDRSTRLEN] = {0}, dst_ip[INET_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET, &(ip->iph_source), src_ip, INET_ADDRSTRLEN) ||
        !inet_ntop(AF_INET, &(ip->iph_dest), dst_ip, INET_ADDRSTRLEN)) {
        tcp = nullptr;
        return;
    }

    key = ConnectionKey(src_ip, ntohs(tcp->th_sport), dst_ip, ntohs(tcp->th_dport));
}

void PacketProcessor::log_packet(const struct pcap_pkthdr* header, const ConnectionKey& key, const tcpheader* tcp) {
    packet_log_.log(std::make_shared<PacketLogEntry>(key, tcp));
}

void PacketProcessor::handle_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    if (!validate_packet(header, packet)) return;

    const tcpheader* tcp = nullptr;
    ConnectionKey key;
    extract_packet_info(packet, key, tcp);
    if (!tcp || key.src_ip.empty() || key.dst_ip.empty()) return;
    
    log_packet(header, key, tcp);
    connection_manager_.process_packet(key, tcp, packet, header->len);
}

void packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    if (!user) return;
    auto* handler = reinterpret_cast<PacketProcessor*>(user);
    handler->handle_packet(header, packet);
}
