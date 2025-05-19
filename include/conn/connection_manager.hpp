#ifndef CONNECTION_MANAGER_HPP
#define CONNECTION_MANAGER_HPP

#include <unordered_map>
#include <deque>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include "conn/connection.hpp"
#include "definitions/packet_key.hpp"
#include "log/log.hpp"

class ConnectionManager {
public:
    ConnectionManager(int cleanup_interval_seconds = 5, std::vector<std::string> default_analyzers = {});
    ~ConnectionManager();

    // Process a packet and update connection state
    void process_packet(const ConnectionKey& key, const PacketKey& pkey);
    
    // Get a connection by key
    Connection* get_connection(const ConnectionKey& key);
    
    // Get all active connections
    std::vector<Connection*> get_active_connections();

private:
    Connection& create_or_get_connection(const ConnectionKey& key, const TCPHeader* tcp);
    void mark_for_cleanup(const ConnectionKey& key);
    void cleanup_marked_connections();
    void cleanup_thread_func();
    
    Connection dummy_connection_;
    std::unordered_map<ConnectionKey, std::unique_ptr<Connection>> connections_;
    std::vector<ConnectionKey> marked_for_cleanup_;
    std::vector<std::string> default_analyzers_;

    int next_id_;
    std::thread cleanup_thread_;
    std::mutex connections_mutex_;
    std::mutex cleanup_mutex_;
    std::atomic<bool> running_;
    int cleanup_interval_seconds_;
};

#endif // CONNECTION_MANAGER_HPP
