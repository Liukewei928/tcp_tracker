#include "tcp/packet_processor.hpp"
#include "log/log_entries.hpp"
#include "tcp/ip_tcp_header.hpp"
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <chrono>
#include <iostream>

PacketProcessor::PacketProcessor(ConsoleDisplay& display, int cleanup_interval_seconds)
    : display_(display), next_id_(1), running_(true), cleanup_interval_seconds_(cleanup_interval_seconds),
      packet_log_("packets.log", true), state_log_("states.log", true) {
    cleanup_thread_ = std::thread(&PacketProcessor::cleanup_thread_func, this);
}

PacketProcessor::~PacketProcessor() {
    running_ = false;
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
    flush_state_log();
}

void PacketProcessor::flush_state_log() {
    state_log_.flush();
}

void PacketProcessor::truncate_packet_log() {
    packet_log_.truncate();
}

void PacketProcessor::truncate_state_log() {
    state_log_.truncate();
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
        (conn.get_client_state() == tcp_state::time_wait || conn.get_server_state() == tcp_state::time_wait)) {
        std::lock_guard<std::mutex> lock(cleanup_mutex_);
        marked_for_cleanup_.push_back(key);
    }
}

Connection& PacketProcessor::create_or_get_connection(const ConnectionKey& key, const tcpheader* tcp) {
    std::unique_lock<std::mutex> lock(connections_mutex_);
    if (!connections_.count(key)) {
        auto conn = std::make_unique<Connection>(key, next_id_++);
        latest_connections_.push_back(conn.get());
        if (latest_connections_.size() > MAX_LATEST) {
            latest_connections_.pop_front();
        }
        connections_[key] = std::move(conn);
    }

    bool is_initiate_flag = (tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK);
	if (is_initiate_flag && !connections_[key]->is_client_initiated()) {
		connections_[key]->initiate_client(key.src_ip);
	}

    return *connections_[key];
}

void PacketProcessor::log_packet_and_state(const struct pcap_pkthdr* header, const ConnectionKey& key, const Connection& conn, const tcpheader* tcp, std::chrono::steady_clock::time_point timestamp, tcp_state prev_client_state, tcp_state prev_server_state) {
    packet_log_.log(std::make_shared<PacketLogEntry>(header, key.src_ip.c_str(), key.dst_ip.c_str(), tcp));
    // Only log state if it changed
    if (conn.get_client_state() != prev_client_state || conn.get_server_state() != prev_server_state) {
        state_log_.log(std::make_shared<StateLogEntry>(key, conn.get_current_state(timestamp), timestamp));
    }
}

void PacketProcessor::handle_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    if (!validate_packet(header, packet)) return;

    const tcpheader* tcp = nullptr;
    ConnectionKey key;
    extract_packet_info(packet, key, tcp);
    if (!tcp || key.src_ip.empty() || key.dst_ip.empty()) return;

    Connection& conn = create_or_get_connection(key, tcp);
    
	// Capture previous states before updating
    tcp_state prev_client_state = conn.get_client_state();
    tcp_state prev_server_state = conn.get_server_state();
    
    auto timestamp = std::chrono::steady_clock::now(); //todo
    conn.update_state(key, tcp->th_flags);
	log_packet_and_state(header, key, conn, tcp, timestamp, prev_client_state, prev_server_state);
    mark_for_cleanup(key, tcp, conn);

    display_.update_connections(latest_connections_);
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
