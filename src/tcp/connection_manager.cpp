#include "tcp/connection_manager.hpp"
#include "tcp/connection.hpp"
#include "tcp_def/reassembly_def.hpp"
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <chrono>
#include <iostream>

ConnectionManager::ConnectionManager(int cleanup_interval_seconds, bool debug_mode)
    : next_id_(1)
    , running_(true)
    , cleanup_interval_seconds_(cleanup_interval_seconds)
    , debug_mode_(debug_mode)
{
    cleanup_thread_ = std::thread(&ConnectionManager::cleanup_thread_func, this);
}

ConnectionManager::~ConnectionManager() {
    running_ = false;
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
}

void ConnectionManager::process_packet(const ConnectionKey& key, const tcpheader* tcp, const u_char* packet, size_t packet_len) {
    if (!tcp || key.src_ip.empty() || key.dst_ip.empty()) return;

    Connection& conn = create_or_get_connection(key, tcp);
    if (conn.get_key().src_ip.empty()) return;

    bool is_from_client = conn.is_from_client(key.src_ip);
    
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

    // Update connection state
    if (is_from_client) {
        conn.update_server_state(tcp->th_flags);
    } else {
        conn.update_client_state(tcp->th_flags);
    }

    // Check if connection should be marked for cleanup
    if ((tcp->th_flags & (TH_FIN | TH_RST)) || 
        (conn.get_client_state() == tcp_state::closed && conn.get_server_state() == tcp_state::closed) ||
        (conn.get_client_state() == tcp_state::time_wait || conn.get_server_state() == tcp_state::time_wait)) {
        mark_for_cleanup(key);
    }
}

Connection* ConnectionManager::get_connection(const ConnectionKey& key) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(key);
    return (it != connections_.end()) ? it->second.get() : nullptr;
}

std::vector<Connection*> ConnectionManager::get_active_connections() {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    std::vector<Connection*> active_connections;
    for (auto& pair : connections_) {
        active_connections.push_back(pair.second.get());
    }
    return active_connections;
}

Connection& ConnectionManager::create_or_get_connection(const ConnectionKey& key, const tcpheader* tcp) {
    std::unique_lock<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(key);
    
    if (it == connections_.end()) {
        bool init_flag = (tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK);
        if (!init_flag) {
            ConnectionKey empty_key;
            auto conn = std::make_unique<Connection>(empty_key, 0);
            return *std::move(conn);
        }

        // Create data callback for reassembly
        auto data_callback = [this](ReassemblyDirection dir, const uint8_t* data, size_t len) {
            if (debug_mode_) {
                std::cout << "Reassembled " << len << " bytes from " 
                          << (dir == ReassemblyDirection::CLIENT_TO_SERVER ? "client->server" : "server->client")
                          << std::endl;
                if (data != nullptr) {
                    std::cerr << "Payload as string: \"" << std::string(reinterpret_cast<const char*>(data), len) 
                              << "\"" << std::endl;
                }
            }
        };

        auto conn = std::make_unique<Connection>(key, next_id_++, debug_mode_, data_callback);
        connections_[key] = std::move(conn);
        return *connections_[key];
    }

    return *it->second;
}

void ConnectionManager::mark_for_cleanup(const ConnectionKey& key) {
    std::lock_guard<std::mutex> lock(cleanup_mutex_);
    marked_for_cleanup_.push_back(key);
}

void ConnectionManager::cleanup_marked_connections() {
    std::vector<ConnectionKey> to_cleanup;
    {
        std::lock_guard<std::mutex> lock(cleanup_mutex_);
        to_cleanup.swap(marked_for_cleanup_);
    }

    if (to_cleanup.empty()) return;

    std::lock_guard<std::mutex> lock(connections_mutex_);
    for (const auto& key : to_cleanup) {
        auto it = connections_.find(key);
        if (it != connections_.end() && it->second->should_clean_up()) {
            connections_.erase(it);
        }
    }
}

void ConnectionManager::cleanup_thread_func() {
    while (running_) {
        cleanup_marked_connections();
        std::this_thread::sleep_for(std::chrono::seconds(cleanup_interval_seconds_));
    }
} 