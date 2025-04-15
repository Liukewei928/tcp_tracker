#ifndef PACKET_PROCESSOR_HPP
#define PACKET_PROCESSOR_HPP

#include <pcap.h>
#include <unordered_map>
#include <deque>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include "tcp/connection.hpp"
#include "tcp_def/ip_tcp_header.hpp"
#include "console/console_display.hpp"
#include "log/log.hpp"

class PacketProcessor {
public:
    PacketProcessor(ConsoleDisplay& display, int cleanup_interval_seconds = 5, bool debug_mode = false);
    ~PacketProcessor();
    void handle_packet(const struct pcap_pkthdr* header, const u_char* packet);

private:
    bool validate_packet(const struct pcap_pkthdr* header, const u_char* packet);
    Connection& create_or_get_connection(const ConnectionKey& key, const tcpheader* tcp);
    void log_packet_and_state(const struct pcap_pkthdr* header, const ConnectionKey& key, const Connection& conn, const tcpheader* tcp, std::chrono::steady_clock::time_point timestamp, tcp_state prev_client_state, tcp_state prev_server_state);
    void mark_for_cleanup(const ConnectionKey& key, const tcpheader* tcp, const Connection& conn);
    void extract_packet_info(const u_char* packet, ConnectionKey& key, const tcpheader*& tcp);
    void cleanup_marked_connections();
    void cleanup_thread_func();

    static constexpr size_t MAX_LATEST = 10;

    ConsoleDisplay& display_;
    std::unordered_map<ConnectionKey, std::unique_ptr<Connection>> connections_;
    std::deque<Connection*> latest_connections_;
    std::vector<ConnectionKey> marked_for_cleanup_;

    int next_id_;
    std::thread cleanup_thread_;
    std::mutex connections_mutex_;
    std::mutex cleanup_mutex_;
    std::atomic<bool> running_;
    int cleanup_interval_seconds_;
   
	Log packet_log_;
	bool debug_mode_;
};

void packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

#endif // PACKET_PROCESSOR_HPP
