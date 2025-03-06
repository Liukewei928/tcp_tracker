#include "connection.hpp"
#include "utils.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <sstream>

ConnectionKey::ConnectionKey(const std::string& src_ip_, uint16_t src_port_, const std::string& dst_ip_, uint16_t dst_port_)
    : src_ip(src_ip_), src_port(src_port_), dst_ip(dst_ip_), dst_port(dst_port_) {}

ConnectionKey ConnectionKey::normalized() const {
    if (src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port)) {
        return *this;
    }
    return ConnectionKey(dst_ip, dst_port, src_ip, src_port);
}

bool ConnectionKey::operator<(const ConnectionKey& other) const {
    return (src_ip + std::to_string(src_port) + dst_ip + std::to_string(dst_port)) <
           (other.src_ip + std::to_string(other.src_port) + other.dst_ip + std::to_string(other.dst_port));
}

bool ConnectionKey::operator==(const ConnectionKey& other) const {
    return src_ip == other.src_ip && src_port == other.src_port &&
           dst_ip == other.dst_ip && dst_port == other.dst_port;
}

Connection::Connection(const ConnectionKey& key, int id)
    : key_(key), id_(id), last_update_(std::chrono::steady_clock::now()) {}

static tcp_state handle_initial_states(uint8_t flags) {
    if (flags == TH_SYN) return tcp_state::syn_sent;
    if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) return tcp_state::syn_received;
    return tcp_state::closed;
}

static tcp_state handle_established_transitions(tcp_state current, uint8_t flags, bool is_client) {
    if (current == tcp_state::syn_received && flags == TH_ACK) return tcp_state::established;
    if (current == tcp_state::established && (flags & TH_FIN)) {
        return is_client ? tcp_state::fin_wait_1 : tcp_state::close_wait;
    }
    return current;
}

static tcp_state handle_closing_states(tcp_state current, uint8_t flags) {
    if (current == tcp_state::fin_wait_1 && (flags & TH_ACK)) return tcp_state::fin_wait_2;
    if (current == tcp_state::close_wait && (flags & TH_FIN)) return tcp_state::last_ack;
    if (current == tcp_state::fin_wait_2 && (flags & TH_ACK)) return tcp_state::time_wait;
    if (current == tcp_state::last_ack && (flags & TH_ACK)) return tcp_state::closed;
    return current;
}

tcp_state determine_new_state(tcp_state current, uint8_t flags, bool is_client) {
    if (flags & TH_RST) return tcp_state::closed;

    tcp_state new_state = handle_initial_states(flags);
    if (new_state != tcp_state::closed) return new_state;

    new_state = handle_established_transitions(current, flags, is_client);
    if (new_state != current) return new_state;

    return handle_closing_states(current, flags);
}

void Connection::update_state(state_info& info, uint8_t flags, bool is_client, std::chrono::steady_clock::time_point timestamp) {
    tcp_state new_state = determine_new_state(info.state, flags, is_client);
    if (new_state != info.state) {
        info.state = new_state;
        info.start_time = timestamp;
        last_update_ = timestamp;
    }
}

void Connection::update_state_client(uint8_t flags, std::chrono::steady_clock::time_point timestamp) {
    update_state(client_state_, flags, true, timestamp);
}

void Connection::update_state_server(uint8_t flags, std::chrono::steady_clock::time_point timestamp) {
    update_state(server_state_, flags, false, timestamp);
}

bool Connection::should_clean_up() const {
    auto now = std::chrono::steady_clock::now();
    if (client_state_.state == tcp_state::closed && server_state_.state == tcp_state::closed) return true;
    if (client_state_.state == tcp_state::time_wait || server_state_.state == tcp_state::time_wait) {
        return std::chrono::duration_cast<std::chrono::seconds>(now - last_update_) >= TIME_WAIT_DURATION;
    }
    return false;
}

static std::string format_duration(std::chrono::steady_clock::time_point now, std::chrono::steady_clock::time_point start) {
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(now - start).count();
    double duration_s = duration_us / 1000000.0;
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(3) << duration_s << " s";
    return oss.str();
}

std::string Connection::get_current_state(std::chrono::steady_clock::time_point now) const {
    tcp_state current = (client_state_.state != tcp_state::closed) ? client_state_.state : server_state_.state;
    std::string state_str = state_to_string(current);
    if (current == tcp_state::established) {
        state_str += "(" + format_duration(now, client_state_.start_time) + ")";
    }
    return state_str;
}

std::string Connection::get_current_state_name() const {
    tcp_state current = (client_state_.state != tcp_state::closed) ? client_state_.state : server_state_.state;
    return state_to_string(current);
}
