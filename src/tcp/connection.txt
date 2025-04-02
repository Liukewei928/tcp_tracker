#include "tcp/connection.hpp"
#include "tcp/ip_tcp_header.hpp"
#include "log/state_log_entry.hpp"
#include <netinet/tcp.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <sstream>

ConnectionKey::ConnectionKey(const std::string& src_ip_, uint16_t src_port_, const std::string& dst_ip_, uint16_t dst_port_)
    : src_ip(src_ip_), src_port(src_port_), dst_ip(dst_ip_), dst_port(dst_port_) {
}

bool ConnectionKey::operator==(const ConnectionKey& other) const {
    // Check if they match directly
	bool direct_match = (src_ip == other.src_ip &&
						 src_port == other.src_port &&
						 dst_ip == other.dst_ip &&
						 dst_port == other.dst_port);

	// Check if they match in reverse
	bool reverse_match = (src_ip == other.dst_ip &&
						  src_port == other.dst_port &&
						  dst_ip == other.src_ip &&
						  dst_port == other.src_port);

	return direct_match || reverse_match;
}

bool ConnectionKey::operator!=(const ConnectionKey& other) const {
	return !(*this == other);
}

const ConnectionKey& ConnectionKey::operator!() const {
	ConnectionKey key(this->dst_ip, this->dst_port, this->src_ip, this->src_port);
	return std::move(key);
}

Connection::Connection(const ConnectionKey& key, int id, bool debug_mode)
    : key_(key), id_(id), last_update_(std::chrono::steady_clock::now()), state_log_("state.log", debug_mode), debug_mode_(debug_mode) {
}

Connection::~Connection() {
	state_log_.flush();
}

tcp_state Connection::determine_new_client_state(tcp_state current, uint8_t flags) {
	if (flags & TH_RST) return tcp_state::closed;
    switch (current) {
        case tcp_state::closed: 
			break;
        case tcp_state::syn_sent:
            if ((flags & TH_SYN) && (flags & TH_ACK)) return tcp_state::established;
            break;
        case tcp_state::established:
            if (flags & TH_FIN) return tcp_state::fin_wait_1;
            break;
        case tcp_state::fin_wait_1:
            if (flags & TH_ACK && !(flags & TH_FIN)) return tcp_state::fin_wait_2;
            if (flags & TH_FIN) return tcp_state::time_wait;
            break;
        case tcp_state::fin_wait_2:
            if (flags & TH_FIN) return tcp_state::time_wait;
            break;
        case tcp_state::time_wait:
            if (flags & TH_ACK) return tcp_state::closed;
            break;
        default: break;
    }
    return current;
}

tcp_state Connection::determine_new_server_state(tcp_state current, uint8_t flags) {
	if (flags & TH_RST) return tcp_state::closed;
    switch (current) {
        case tcp_state::closed:
            if (flags & TH_SYN && !(flags & TH_ACK)) return tcp_state::syn_received;
            break;
        case tcp_state::syn_received:
            if (flags & TH_ACK && !(flags & TH_SYN)) return tcp_state::established;
            break;
        case tcp_state::established:
            if (flags & TH_FIN) return tcp_state::close_wait;
            break;
        case tcp_state::close_wait: break;
        case tcp_state::last_ack:
            if (flags & TH_ACK) return tcp_state::closed;
            break;
        default: break;
    }
    return current;
}

void Connection::update_client_state(uint8_t flags) {
	tcp_state new_state = determine_new_client_state(client_state_.state, flags);
    printf("old:%d,new:%d\n",client_state_.state, new_state);
	if (new_state != client_state_.state) {
		auto timestamp = std::chrono::steady_clock::now();
		client_state_.prev_state = client_state_.state;
		client_state_.state = new_state;
        state_log_.log(std::make_shared<StateLogEntry>(key_, get_state_change_info(timestamp)));
		
		client_state_.state = new_state;
        client_state_.start_time = timestamp;
        last_update_ = timestamp;
    }
}

void Connection::update_server_state(uint8_t flags) {
    tcp_state new_state = determine_new_server_state(server_state_.state, flags);
    if (new_state != server_state_.state) {
        auto timestamp = std::chrono::steady_clock::now();
		server_state_.prev_state = server_state_.state;
        server_state_.state = new_state;
        state_log_.log(std::make_shared<StateLogEntry>(!key_, get_state_change_info(timestamp)));

        server_state_.start_time = timestamp;
        last_update_ = timestamp;
    }
}

bool Connection::is_from_client(const std::string& pkt_src_ip) const {
	return key_.src_ip == pkt_src_ip;
}

bool Connection::should_clean_up() const {
    auto now = std::chrono::steady_clock::now();
    if (client_state_.state == tcp_state::closed && server_state_.state == tcp_state::closed) return true;
    if (client_state_.state == tcp_state::time_wait || server_state_.state == tcp_state::time_wait) {
        return std::chrono::duration_cast<std::chrono::seconds>(now - last_update_) >= TIME_WAIT_DURATION;
    }
    return false;
}

std::string Connection::get_state_change_info(std::chrono::steady_clock::time_point now) const {
    std::ostringstream oss;
    oss << "cli:" << state_to_string(client_state_.state);
    if (client_state_.prev_state == tcp_state::established && client_state_.state != tcp_state::established) {
        auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(now - client_state_.start_time).count();
        double duration_s = duration_us / 1000000.0;
        oss << "(" << std::fixed << std::setprecision(3) << duration_s << " s)";
    }
    oss << " srv:" << state_to_string(server_state_.state);
    if (server_state_.prev_state == tcp_state::established && server_state_.state != tcp_state::established) {
        auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(now - server_state_.start_time).count();
        double duration_s = duration_us / 1000000.0;
        oss << "(" << std::fixed << std::setprecision(3) << duration_s << " s)";
    }
    return oss.str();
}
