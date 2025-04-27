#include "conn/tcp_state_machine.hpp"
#include <netinet/tcp.h>
#include <chrono>

std::string TcpStateMachine::flags_to_string(uint8_t flags) {
    std::string s = "";
    if (flags & TH_SYN) s += "S";
    if (flags & TH_ACK) s += "A";
    if (flags & TH_FIN) s += "F";
    if (flags & TH_RST) s += "R";
    if (flags & TH_PUSH) s += "P";
    if (flags & TH_URG) s += "U";
    if (s.empty()) s = "-";
    return s;
}

std::string TcpStateMachine::state_to_string(tcp_state s) {
    switch (s) {
        case tcp_state::closed: return "CLOSED";
        case tcp_state::listen: return "LISTEN";
        case tcp_state::syn_sent: return "SYN_SENT";
        case tcp_state::syn_received: return "SYN_RCVD";
        case tcp_state::established: return "ESTABLISHED";
        case tcp_state::fin_wait_1: return "FIN_WAIT_1";
        case tcp_state::fin_wait_2: return "FIN_WAIT_2";
        case tcp_state::close_wait: return "CLOSE_WAIT";
        case tcp_state::closing: return "CLOSING";
        case tcp_state::last_ack: return "LAST_ACK";
        case tcp_state::time_wait: return "TIME_WAIT";
        default: return "UNKNOWN";
    }
}

tcp_state TcpStateMachine::client_state_machine(tcp_state current, uint8_t flags) {
    if (flags & TH_RST) return tcp_state::closed;
    switch (current) {
        case tcp_state::closed: break;
        case tcp_state::listen: break;
        case tcp_state::syn_sent:
            if ((flags & TH_SYN) && (flags & TH_ACK)) return tcp_state::established;
            if (flags & TH_SYN) return tcp_state::syn_received;
            break;
        case tcp_state::syn_received:
            if (flags & TH_ACK) return tcp_state::established;
            if (flags & TH_FIN) return tcp_state::close_wait;
            break;
        case tcp_state::established:
            if (flags & TH_FIN) return tcp_state::close_wait;
            break;
        case tcp_state::fin_wait_1:
            if ((flags & TH_FIN) && (flags & TH_ACK)) return tcp_state::time_wait;
            if (flags & TH_ACK) return tcp_state::fin_wait_2;
            if (flags & TH_FIN) return tcp_state::closing;
            break;
        case tcp_state::fin_wait_2:
            if (flags & TH_FIN) return tcp_state::time_wait;
            break;
        case tcp_state::close_wait: break;
        case tcp_state::closing:
            if (flags & TH_ACK) return tcp_state::time_wait;
            break;
        case tcp_state::last_ack:
            if (flags & TH_ACK) return tcp_state::closed;
            break;
        case tcp_state::time_wait: break;
        default: break;
    }
    return current;
}

tcp_state TcpStateMachine::server_state_machine(tcp_state current, uint8_t flags) {
    if (flags & TH_RST) return tcp_state::closed;
    switch (current) {
        case tcp_state::closed: break;
        case tcp_state::listen:
            if ((flags & TH_SYN) && !(flags & TH_ACK)) return tcp_state::syn_received;
            break;
        case tcp_state::syn_sent: break;
        case tcp_state::syn_received:
            if (flags & TH_ACK) return tcp_state::established;
            if (flags & TH_FIN) return tcp_state::close_wait;
            break;
        case tcp_state::established:
            if (flags & TH_FIN) return tcp_state::close_wait;
            break;
        case tcp_state::fin_wait_1:
            if ((flags & TH_FIN) && (flags & TH_ACK)) return tcp_state::time_wait;
            if (flags & TH_ACK) return tcp_state::fin_wait_2;
            if (flags & TH_FIN) return tcp_state::closing;
            break;
        case tcp_state::fin_wait_2:
            if (flags & TH_FIN) return tcp_state::time_wait;
            break;
        case tcp_state::close_wait: break;
        case tcp_state::closing:
            if (flags & TH_ACK) return tcp_state::time_wait;
            break;
        case tcp_state::last_ack:
            if (flags & TH_ACK) return tcp_state::closed;
            break;
        case tcp_state::time_wait: break;
        default: break;
    }
    return current;
}

tcp_state TcpStateMachine::determine_new_state(tcp_state current, uint8_t flags, bool is_client) {
    return is_client ? client_state_machine(current, flags) : server_state_machine(current, flags);
}

bool TcpStateMachine::should_enter_time_wait(tcp_state current, uint8_t flags, bool is_client) {
    if (is_client) {
        return (current == tcp_state::fin_wait_1 && ((flags & TH_FIN) && (flags & TH_ACK))) ||
               (current == tcp_state::fin_wait_2 && (flags & TH_FIN)) ||
               (current == tcp_state::closing && (flags & TH_ACK));
    } else {
        return (current == tcp_state::fin_wait_1 && ((flags & TH_FIN) && (flags & TH_ACK))) ||
               (current == tcp_state::fin_wait_2 && (flags & TH_FIN)) ||
               (current == tcp_state::closing && (flags & TH_ACK));
    }
}

bool TcpStateMachine::should_clean_up(const State& client_state, const State& server_state, 
                                    const std::chrono::steady_clock::time_point& last_update) const     {
    auto now = std::chrono::steady_clock::now();

    // 1. If both sides have definitively reached CLOSED state
    if (client_state.state == tcp_state::closed && server_state.state == tcp_state::closed) {
        return true;
    }

    // 2. Handle TIME_WAIT timeout
    bool client_timed_out = false;
    if (client_state.state == tcp_state::time_wait && client_state.time_wait_entry_time.has_value()) {
        client_timed_out = (now - client_state.time_wait_entry_time.value()) >= TIME_WAIT_DURATION;
    }

    bool server_timed_out = false;
    if (server_state.state == tcp_state::time_wait && server_state.time_wait_entry_time.has_value()) {
        server_timed_out = (now - server_state.time_wait_entry_time.value()) >= TIME_WAIT_DURATION;
    }

    // Cleanup if either side's TIME_WAIT has expired
    if (client_timed_out || server_timed_out) {
        return true;
    }

    // 3. Cleanup after long inactivity
    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_update) > MAX_INACTIVITY) {
        return true;
    }

    return false;
} 