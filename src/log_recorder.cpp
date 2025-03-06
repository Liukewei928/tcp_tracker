#include "log_recorder.hpp"
#include <pcap.h>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <iostream>
#include "tcp_state.hpp"

LogRecorder::LogRecorder(bool debug_mode, bool state_log_mode, int flush_updates, int flush_minutes)
    : debug_mode_(debug_mode), state_log_mode_(state_log_mode), flush_updates_(flush_updates), flush_minutes_(flush_minutes),
      update_count_(0), last_flush_time_(std::chrono::steady_clock::now()) {
    if (debug_mode_) {
        packet_log_.open("packets.log", std::ios::app);
        if (!packet_log_.is_open()) std::cerr << "Failed to open packets.log" << std::endl;
    }
    if (state_log_mode_) {
        state_log_file_.open("states.log", std::ios::app);
        if (!state_log_file_.is_open()) std::cerr << "Failed to open states.log" << std::endl;
    }
}

LogRecorder::~LogRecorder() {
    if (state_log_mode_ && state_log_file_.is_open()) {
        flush_state_log();
        state_log_file_.close();
    }
    if (debug_mode_ && packet_log_.is_open()) {
        packet_log_.close();
    }
}

static std::string format_packet_flags(const tcpheader* tcp) {
    std::ostringstream oss;
    oss << "flags: ";
    if (tcp->th_flags & TH_FIN) oss << "fin ";
    if (tcp->th_flags & TH_SYN) oss << "syn ";
    if (tcp->th_flags & TH_RST) oss << "rst ";
    if (tcp->th_flags & TH_PUSH) oss << "psh ";
    if (tcp->th_flags & TH_ACK) oss << "ack ";
    if (tcp->th_flags & TH_URG) oss << "urg ";
    oss << "\n";
    return oss.str();
}

void LogRecorder::log_packet(const struct pcap_pkthdr* header, const char* src_ip, const char* dst_ip, const tcpheader* tcp) {
    if (!debug_mode_ || !packet_log_.is_open()) return;
    check_log_size("packets.log");
    std::ostringstream oss;
    auto time_t = header->ts.tv_sec;
    oss << "[" << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S.")
        << std::setfill('0') << std::setw(6) << header->ts.tv_usec << " UTC] tcp_packet:\n"
        << "src: " << src_ip << ":" << ntohs(tcp->th_sport) << "\n"
        << "dst: " << dst_ip << ":" << ntohs(tcp->th_dport) << "\n"
        << format_packet_flags(tcp);
    packet_log_ << oss.str() << std::endl;
}

void LogRecorder::log_state_transition(const ConnectionKey& key, const std::string& state, std::chrono::steady_clock::time_point now) {
    if (!state_log_mode_ || !state_log_file_.is_open()) return;

    auto state_name_it = last_states_.find(key);
    std::string state_name = state.substr(0, state.find('('));
    bool is_initial = (state_name_it == last_states_.end());

    // Start logging only with handshake states, but continue logging all transitions thereafter
    if (is_initial && state_name != "syn_sent" && state_name != "syn_received") {
        return;
    }

    if (is_initial || state_name_it->second != state_name) {
        auto timestamp = std::chrono::system_clock::now();
        std::ostringstream oss;
        oss << key.src_ip << ":" << key.src_port << " -> " << key.dst_ip << ":" << key.dst_port << " ";

        if (state_logs_.count(key)) {
            state_logs_[key] += " -> " + state;
        } else {
            state_logs_[key] = state;
            handshake_started_[key] = true;
        }
        state_timestamps_[key] = timestamp;
        last_states_[key] = state_name;
        last_flush_times_[key] = now;

        update_count_++;
        auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now() - last_flush_time_).count();
        if (update_count_ >= flush_updates_ || elapsed >= flush_minutes_) {
            flush_state_log();
            update_count_ = 0;
            last_flush_time_ = std::chrono::steady_clock::now();
        }
    } else if (state_name == "established") {
        state_logs_[key] = state_logs_[key].substr(0, state_logs_[key].rfind(" -> ")) + " -> " + state;
        state_timestamps_[key] = std::chrono::system_clock::now();
        last_flush_times_[key] = now;
    }
}

void LogRecorder::log_cleanup(const ConnectionKey& key) {
    if (!debug_mode_ || !packet_log_.is_open()) return;
    check_log_size("packets.log");
    std::ostringstream oss;
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    oss << "[" << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S.")
        << std::setfill('0') << std::setw(6) << 0 << " UTC] cleaning_up_connection: "
        << key.src_ip << ":" << key.src_port << " -> " << key.dst_ip << ":" << key.dst_port;
    packet_log_ << oss.str() << std::endl;

    if (state_log_mode_) {
        state_logs_.erase(key);
        state_timestamps_.erase(key);
        last_states_.erase(key);
        last_flush_times_.erase(key);
        handshake_started_.erase(key);
    }
}

static std::string format_state_entry(const ConnectionKey& key, const std::string& state, std::chrono::system_clock::time_point timestamp) {
    std::ostringstream oss;
    auto time_t_val = std::chrono::system_clock::to_time_t(timestamp);
    oss << "[" << std::put_time(std::gmtime(&time_t_val), "%Y-%m-%d %H:%M:%S.")
        << std::setfill('0') << std::setw(6)
        << std::chrono::duration_cast<std::chrono::microseconds>(timestamp.time_since_epoch()).count() % 1000000
        << " UTC] " << key.src_ip << ":" << key.src_port << " -> " << key.dst_ip << ":" << key.dst_port << " " << state;
    return oss.str();
}

void LogRecorder::flush_state_log() {
    if (!state_log_mode_ || !state_log_file_.is_open()) return;
    check_log_size("states.log");

    std::vector<std::pair<ConnectionKey, std::chrono::system_clock::time_point>> sorted_entries;
    {
        for (const auto& [key, timestamp] : state_timestamps_) {
            sorted_entries.emplace_back(key, timestamp);
        }
        std::sort(sorted_entries.begin(), sorted_entries.end(),
                  [](const auto& a, const auto& b) { return a.second < b.second; });
    }

    for (const auto& [key, timestamp] : sorted_entries) {
        state_log_file_ << format_state_entry(key, state_logs_[key], timestamp) << std::endl;
    }
    state_log_file_.flush();
}

void LogRecorder::check_log_size(const std::string& filename) {
    if (std::filesystem::exists(filename) && std::filesystem::file_size(filename) > MAX_LOG_SIZE) {
        truncate_log(filename);
    }
}

void LogRecorder::truncate_log(const std::string& filename) {
    std::ofstream ofs(filename, std::ios::trunc);
    ofs << "Log truncated due to size limit\n";
    ofs.close();
    if (filename == "packets.log") {
        packet_log_.close();
        packet_log_.open("packets.log", std::ios::app);
    } else if (filename == "states.log") {
        state_log_file_.close();
        state_log_file_.open("states.log", std::ios::app);
    }
}
