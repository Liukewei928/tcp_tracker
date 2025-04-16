#include "tcp/packet_processor.hpp"
#include "log/packet_log_entry.hpp"
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <chrono>
#include <iostream>

PacketProcessor::PacketProcessor(ConsoleDisplay& display, int cleanup_interval_seconds, bool debug_mode)
    : display_(display), next_id_(1), running_(true), cleanup_interval_seconds_(cleanup_interval_seconds),
 packet_log_("packet.log", debug_mode), debug_mode_(debug_mode) {
    cleanup_thread_ = std::thread(&PacketProcessor::cleanup_thread_func, this);
}

PacketProcessor::~PacketProcessor() {
    running_ = false;
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
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

void PacketProcessor::mark_for_cleanup(const ConnectionKey& key, const tcpheader* tcp, const Connection& conn) {
    if ((tcp->th_flags & (TH_FIN | TH_RST)) || 
        (conn.get_client_state() == tcp_state::closed && conn.get_server_state() == tcp_state::closed) ||
        (conn.get_client_state() == tcp_state::time_wait || conn.get_server_state() == tcp_state::time_wait)) 	 {
		if (conn.get_key().src_ip == "") return;
        std::lock_guard<std::mutex> lock(cleanup_mutex_);
        marked_for_cleanup_.push_back(key);
    }
}

Connection& PacketProcessor::create_or_get_connection(const ConnectionKey& key, const tcpheader* tcp) {
    std::unique_lock<std::mutex> lock(connections_mutex_);
    if (!connections_.count(key)) {
        bool init_flag = (tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK);
        if (!init_flag) {
            ConnectionKey empty_key;
            auto conn = std::make_unique<Connection>(empty_key, 0);
            return *std::move(conn);
        }       

        // Create data callback for reassembly
        auto data_callback = [this](ReassemblyDirection dir, const uint8_t* data, size_t len) {
            // Here you can implement what to do with reassembled data
            // For example, log it, process it, or forward it
            if (debug_mode_) {
                std::cout << "Reassembled " << len << " bytes from " 
                          << (dir == ReassemblyDirection::CLIENT_TO_SERVER ? "client->server" : "server->client")
                          << std::endl;
                if (data != nullptr)
                {
                    std::cerr << "Payload as string: \"" << std::string(reinterpret_cast<const char*>(data), len) 
                        << "\"" << std::endl;
                }
            }
        };

        auto conn = std::make_unique<Connection>(key, next_id_++, debug_mode_, data_callback);
        latest_connections_.push_back(conn.get());
        if (latest_connections_.size() > MAX_LATEST) {
            latest_connections_.pop_front();
        }
        connections_[key] = std::move(conn);
    }

    return *connections_[key];
}

void PacketProcessor::process_payload(Connection& conn, const u_char* packet, const tcpheader* tcp, bool is_from_client) {
    // Extract payload information
    const auto* ip = reinterpret_cast<const ipheader*>(packet + 14);
    int ip_header_len = ip->iph_ihl * 4;
    int tcp_header_len = tcp->th_off * 4;
    const uint8_t* payload = packet + 14 + ip_header_len + tcp_header_len;
    size_t payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    // Process payload if present
    if (payload_len > 0 || (tcp->th_flags & (TH_SYN | TH_FIN))) {
        conn.process_payload(is_from_client, ntohl(tcp->th_seq), payload, payload_len, tcp->th_flags);
    }
}

void PacketProcessor::handle_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    if (!validate_packet(header, packet)) return;

    const tcpheader* tcp = nullptr;
    ConnectionKey key;
    extract_packet_info(packet, key, tcp);
    if (!tcp || key.src_ip.empty() || key.dst_ip.empty()) return;
	
    packet_log_.log(std::make_shared<PacketLogEntry>(key, tcp));
    Connection& conn = create_or_get_connection(key, tcp);

	if (conn.get_key().src_ip.empty()) return;

	bool is_from_client = conn.is_from_client(key.src_ip);
	
    // Process payload using the new method
    process_payload(conn, packet, tcp, is_from_client);

	if (is_from_client)
    	conn.update_server_state(tcp->th_flags);
    else
		conn.update_client_state(tcp->th_flags);

    mark_for_cleanup(key, tcp, conn);

    // display_.update_connections(latest_connections_);
}

void PacketProcessor::cleanup_marked_connections() {
    std::vector<ConnectionKey> to_cleanup;
    {
        std::lock_guard<std::mutex> lock(cleanup_mutex_);
        to_cleanup.swap(marked_for_cleanup_);
    }

    if (to_cleanup.empty()) return;

    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto now = std::chrono::system_clock::now();
    for (const auto& key : to_cleanup) {
        auto it = connections_.find(key);
        if (it != connections_.end() && it->second->should_clean_up()) {
            connections_.erase(it);
            auto latest_it = std::find(latest_connections_.begin(), latest_connections_.end(), it->second.get());
            if (latest_it != latest_connections_.end()) {
                latest_connections_.erase(latest_it);
            }
        }
    }
    display_.update_connections(latest_connections_);
}

void PacketProcessor::cleanup_thread_func() {
    while (running_) {
        cleanup_marked_connections();
        std::this_thread::sleep_for(std::chrono::seconds(cleanup_interval_seconds_));
    }
}

void packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    if (!user) return;
    auto* handler = reinterpret_cast<PacketProcessor*>(user);
    handler->handle_packet(header, packet);
}
