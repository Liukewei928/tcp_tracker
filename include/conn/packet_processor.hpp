#ifndef PACKET_PROCESSOR_HPP
#define PACKET_PROCESSOR_HPP

#include <pcap.h>
#include "conn/connection_manager.hpp"
#include "definations/packet_key.hpp"
#include "log/log_manager.hpp"

class PacketProcessor {
public:
    PacketProcessor(ConnectionManager& connection_manager);
    ~PacketProcessor();
    void handle_packet(const struct pcap_pkthdr* header, const u_char* packet);

private:
    bool validate_packet(const struct pcap_pkthdr* header, const u_char* packet);
    bool extract_packet(const u_char* packet, const size_t packet_len, 
        ConnectionKey& key, PacketKey& pkey);

    ConnectionManager& connection_manager_;
    Log& packet_log_ = LogManager::get_instance().get_registered_log("packet.log");
};

void packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

#endif // PACKET_PROCESSOR_HPP
