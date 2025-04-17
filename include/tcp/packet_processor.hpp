#ifndef PACKET_PROCESSOR_HPP
#define PACKET_PROCESSOR_HPP

#include <pcap.h>
#include "tcp/connection_manager.hpp"
#include "tcp_def/ip_tcp_header.hpp"
#include "log/log.hpp"

class PacketProcessor {
public:
    PacketProcessor(ConnectionManager& connection_manager, bool debug_mode = false);
    ~PacketProcessor();

    void handle_packet(const struct pcap_pkthdr* header, const u_char* packet);
    
    // Get access to the connection manager for other modules
    ConnectionManager& get_connection_manager() { return connection_manager_; }

private:
    bool validate_packet(const struct pcap_pkthdr* header, const u_char* packet);
    void extract_packet_info(const u_char* packet, ConnectionKey& key, const tcpheader*& tcp);
    void log_packet(const struct pcap_pkthdr* header, const ConnectionKey& key, const tcpheader* tcp);
    
    ConnectionManager& connection_manager_;
    Log packet_log_;
};

void packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

#endif // PACKET_PROCESSOR_HPP
