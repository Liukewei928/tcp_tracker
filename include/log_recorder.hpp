#ifndef LOG_RECORDER_HPP
#define LOG_RECORDER_HPP

#include <unordered_map>
#include <fstream>
#include <chrono>
#include <pcap.h>  // For tcpheader
#include "connection.hpp"
#include "utils.hpp"

class LogRecorder {
public:
    LogRecorder(bool debug_mode = false, bool state_log_mode = false, int flush_updates = 1000, int flush_minutes = 5);
    ~LogRecorder();
    void log_packet(const struct pcap_pkthdr* header, const char* src_ip, const char* dst_ip, const tcpheader* tcp);
    void log_state_transition(const ConnectionKey& key, const std::string& state, std::chrono::steady_clock::time_point now);
    void log_cleanup(const ConnectionKey& key);
    void flush_state_log();

private:
    void check_log_size(const std::string& filename);
    void truncate_log(const std::string& filename);

    bool debug_mode_;
    bool state_log_mode_;
    int flush_updates_;
    int flush_minutes_;
    int update_count_ = 0;
    std::chrono::steady_clock::time_point last_flush_time_;
    std::ofstream packet_log_;
    std::unordered_map<ConnectionKey, std::string> state_logs_;
    std::unordered_map<ConnectionKey, std::string> last_states_;
    std::unordered_map<ConnectionKey, std::chrono::steady_clock::time_point> last_flush_times_;
    std::unordered_map<ConnectionKey, std::chrono::system_clock::time_point> state_timestamps_;
    std::unordered_map<ConnectionKey, bool> handshake_started_;
    std::ofstream state_log_file_;
    static constexpr size_t MAX_LOG_SIZE = 10 * 1024 * 1024; // 10 MB
};

#endif // LOG_RECORDER_HPP
