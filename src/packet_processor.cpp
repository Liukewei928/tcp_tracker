#include "packet_processor.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <iostream>

PacketProcessor::PacketProcessor(ConsoleDisplay& display, LogRecorder& logger, int cleanup_interval_seconds)
    : display_(display), logger_(logger), next_id_(1), running_(true), cleanup_interval_seconds_(cleanup_interval_seconds) {
    cleanup_thread_ = std::thread(&PacketProcessor::cleanup_thread_func, this);
}

PacketProcessor::~PacketProcessor() {
    running_ = false;
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
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

bool PacketProcessor::is_client_packet(const tcpheader* tcp) {
    return tcp && (tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK);
}

void PacketProcessor::update_connection(Connection& conn, const tcpheader* tcp, std::chrono::steady_clock::time_point timestamp) {
    if (is_client_packet(tcp)) {
        conn.update_state_client(tcp->th_flags, timestamp);
    } else if (tcp->th_flags & TH_SYN) {  // SYN-ACK from server
        conn.update_state_server(tcp->th_flags, timestamp);
    } else if (tcp->th_flags & TH_ACK && !(tcp->th_flags & (TH_SYN | TH_FIN | TH_RST))) {  // Pure ACK for handshake completion
        if (conn.get_client_state() == tcp_state::syn_sent || conn.get_server_state() == tcp_state::syn_received) {
            conn.update_state_client(tcp->th_flags, timestamp);  // Complete handshake
        }
    } else {
        conn.update_state_server(tcp->th_flags, timestamp);  // Other server responses
    }
}

void PacketProcessor::mark_for_cleanup(const ConnectionKey& key, const tcpheader* tcp, const Connection& conn) {
    if ((tcp->th_flags & (TH_FIN | TH_RST)) || 
        (conn.get_client_state() == tcp_state::closed && conn.get_server_state() == tcp_state::closed) ||
        (conn.get_client_state() == tcp_state::time_wait || conn.get_server_state() == tcp_state::time_wait)) {
        std::lock_guard<std::mutex> lock(cleanup_mutex_);
        marked_for_cleanup_.push_back(key);
    }
}

void PacketProcessor::process_tcp_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    const tcpheader* tcp = nullptr;
    ConnectionKey key;
    extract_packet_info(packet, key, tcp);
    if (!tcp || key.src_ip.empty() || key.dst_ip.empty()) return;

    ConnectionKey normalized_key = key.normalized();
    auto timestamp = std::chrono::steady_clock::now();

    std::unique_lock<std::mutex> lock(connections_mutex_);
    if (!connections_.count(normalized_key)) {
        auto conn = std::make_unique<Connection>(normalized_key, next_id_++);
        latest_connections_.push_back(conn.get());
        if (latest_connections_.size() > MAX_LATEST) {
            latest_connections_.pop_front();
        }
        connections_[normalized_key] = std::move(conn);
    }

    auto& conn = *connections_[normalized_key];
    update_connection(conn, tcp, timestamp);
    lock.unlock();

    logger_.log_packet(header, key.src_ip.c_str(), key.dst_ip.c_str(), tcp);
    logger_.log_state_transition(normalized_key, conn.get_current_state(timestamp), timestamp);
    mark_for_cleanup(normalized_key, tcp, conn);

    display_.update_connections(latest_connections_);
}

void PacketProcessor::handle_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    if (!validate_packet(header, packet)) return;
    process_tcp_packet(header, packet);
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
            logger_.log_cleanup(it->first);

            auto latest_it = std::find(latest_connections_.begin(), latest_connections_.end(), it->second.get());
            if (latest_it != latest_connections_.end()) {
                latest_connections_.erase(latest_it);
            }
            connections_.erase(it);
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
