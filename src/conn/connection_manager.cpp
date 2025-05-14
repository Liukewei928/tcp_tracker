#include "conn/connection_manager.hpp"
#include "conn/connection.hpp"
#include "definations/reassembly_def.hpp"
#include "reassm/analyzer_registry.hpp"
#include "tls/tls_analyzer.hpp"
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <chrono>
#include <iostream>

ConnectionManager::ConnectionManager(int cleanup_interval_seconds, std::vector<std::string> default_analyzers)
    : next_id_(1)
    , running_(true)
    , cleanup_interval_seconds_(cleanup_interval_seconds)
    , default_analyzers_(std::move(default_analyzers))
{
    cleanup_thread_ = std::thread(&ConnectionManager::cleanup_thread_func, this);
}

ConnectionManager::~ConnectionManager() {
    running_ = false;
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
}

void ConnectionManager::process_packet(const ConnectionKey& key, const PacketKey& pkey) {
    if (!pkey.tcp || key.src_ip.empty() || key.dst_ip.empty()) return;

    Connection& conn = create_or_get_connection(key, pkey.tcp);
    if (conn.get_key().src_ip.empty()) return;

    bool is_from_client = conn.is_from_client(key.src_ip);

    if (pkey.payload_len > 0 || (pkey.tcp->th_flags & (TH_SYN | TH_FIN))) {
        conn.process_payload(is_from_client, ntohl(pkey.tcp->th_seq), 
            pkey.payload, pkey.payload_len, pkey.tcp->th_flags);
    }

    // Update connection state
    if (is_from_client) {
        conn.update_server_state(pkey.tcp->th_flags);
    } else {
        conn.update_client_state(pkey.tcp->th_flags);
    }

    // Check if connection should be marked for cleanup
    if ((pkey.tcp->th_flags & (TH_FIN | TH_RST)) || 
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

Connection& ConnectionManager::create_or_get_connection(const ConnectionKey& key, const TCPHeader* tcp) {
    std::unique_lock<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(key);
    
    if (it == connections_.end()) {
        bool init_flag = (tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK);
        if (!init_flag) {
            return dummy_connection_;
        }

        auto conn = std::make_unique<Connection>(key, next_id_++);
        for (const auto& analyzer : default_analyzers_) {
            conn->add_analyzer(AnalyzerRegistry::get_instance().create_analyzer(analyzer, key));
        }

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
