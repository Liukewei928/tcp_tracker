#ifndef PACKET_PROCESSOR_HPP
#define PACKET_PROCESSOR_HPP

#include <pcap.h>
#include <unordered_map>
#include <deque>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include "utils.hpp"
#include "connection.hpp"
#include "console_display.hpp"
#include "log_recorder.hpp"

class PacketProcessor {
public:
    PacketProcessor(ConsoleDisplay& display, LogRecorder& logger, int cleanup_interval_seconds = 5);
    ~PacketProcessor();
    void handle_packet(const struct pcap_pkthdr* header, const u_char* packet);

private:
    bool validate_packet(const struct pcap_pkthdr* header, const u_char* packet);
    void process_tcp_packet(const struct pcap_pkthdr* header, const u_char* packet);
    void update_connection(Connection& conn, const tcpheader* tcp, std::chrono::steady_clock::time_point timestamp);
    void mark_for_cleanup(const ConnectionKey& key, const tcpheader* tcp, const Connection& conn);
    void extract_packet_info(const u_char* packet, ConnectionKey& key, const tcpheader*& tcp);
    bool is_client_packet(const tcpheader* tcp);
    void cleanup_marked_connections();
    void cleanup_thread_func();

    ConsoleDisplay& display_;
    LogRecorder& logger_;
    std::unordered_map<ConnectionKey, std::unique_ptr<Connection>> connections_;
    std::deque<Connection*> latest_connections_;
    std::vector<ConnectionKey> marked_for_cleanup_;
    int next_id_;
    std::thread cleanup_thread_;
    std::mutex connections_mutex_;
    std::mutex cleanup_mutex_;
    std::atomic<bool> running_;
    int cleanup_interval_seconds_;
    static constexpr size_t MAX_LATEST = 10;
};

void packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

#endif // PACKET_PROCESSOR_HPP
