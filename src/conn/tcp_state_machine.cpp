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

std::string TcpStateMachine::state_to_string(TCPState s) {
    switch (s) {
        case TCPState::CLOSED: return "CLOSED";
        case TCPState::LISTEN: return "LISTEN";
        case TCPState::SYN_SENT: return "SYN_SENT";
        case TCPState::SYN_RECEIVED: return "SYN_RCVD";
        case TCPState::ESTABLISHED: return "ESTABLISHED";
        case TCPState::FIN_WAIT_1: return "FIN_WAIT_1";
        case TCPState::FIN_WAIT_2: return "FIN_WAIT_2";
        case TCPState::CLOSE_WAIT: return "CLOSE_WAIT";
        case TCPState::CLOSING: return "CLOSING";
        case TCPState::LAST_ACK: return "LAST_ACK";
        case TCPState::TIME_WAIT: return "TIME_WAIT";
        default: return "UNKNOWN";
    }
}

TCPState TcpStateMachine::client_state_machine(TCPState current, uint8_t flags) {
    if (flags & TH_RST) return TCPState::CLOSED;
    switch (current) {
        case TCPState::CLOSED: break;
        case TCPState::LISTEN: break;
        case TCPState::SYN_SENT:
            if ((flags & TH_SYN) && (flags & TH_ACK)) return TCPState::ESTABLISHED;
            if (flags & TH_SYN) return TCPState::SYN_RECEIVED;
            break;
        case TCPState::SYN_RECEIVED:
            if (flags & TH_ACK) return TCPState::ESTABLISHED;
            if (flags & TH_FIN) return TCPState::CLOSE_WAIT;
            break;
        case TCPState::ESTABLISHED:
            if (flags & TH_FIN) return TCPState::CLOSE_WAIT;
            break;
        case TCPState::FIN_WAIT_1:
            if ((flags & TH_FIN) && (flags & TH_ACK)) return TCPState::TIME_WAIT;
            if (flags & TH_ACK) return TCPState::FIN_WAIT_2;
            if (flags & TH_FIN) return TCPState::CLOSING;
            break;
        case TCPState::FIN_WAIT_2:
            if (flags & TH_FIN) return TCPState::TIME_WAIT;
            break;
        case TCPState::CLOSE_WAIT: break;
        case TCPState::CLOSING:
            if (flags & TH_ACK) return TCPState::TIME_WAIT;
            break;
        case TCPState::LAST_ACK:
            if (flags & TH_ACK) return TCPState::CLOSED;
            break;
        case TCPState::TIME_WAIT: break;
        default: break;
    }
    return current;
}

TCPState TcpStateMachine::server_state_machine(TCPState current, uint8_t flags) {
    if (flags & TH_RST) return TCPState::CLOSED;
    switch (current) {
        case TCPState::CLOSED: break;
        case TCPState::LISTEN:
            if ((flags & TH_SYN) && !(flags & TH_ACK)) return TCPState::SYN_RECEIVED;
            break;
        case TCPState::SYN_SENT: break;
        case TCPState::SYN_RECEIVED:
            if (flags & TH_ACK) return TCPState::ESTABLISHED;
            if (flags & TH_FIN) return TCPState::CLOSE_WAIT;
            break;
        case TCPState::ESTABLISHED:
            if (flags & TH_FIN) return TCPState::CLOSE_WAIT;
            break;
        case TCPState::FIN_WAIT_1:
            if ((flags & TH_FIN) && (flags & TH_ACK)) return TCPState::TIME_WAIT;
            if (flags & TH_ACK) return TCPState::FIN_WAIT_2;
            if (flags & TH_FIN) return TCPState::CLOSING;
            break;
        case TCPState::FIN_WAIT_2:
            if (flags & TH_FIN) return TCPState::TIME_WAIT;
            break;
        case TCPState::CLOSE_WAIT: break;
        case TCPState::CLOSING:
            if (flags & TH_ACK) return TCPState::TIME_WAIT;
            break;
        case TCPState::LAST_ACK:
            if (flags & TH_ACK) return TCPState::CLOSED;
            break;
        case TCPState::TIME_WAIT: break;
        default: break;
    }
    return current;
}

TCPState TcpStateMachine::determine_new_state(TCPState current, uint8_t flags, bool is_client) {
    return is_client ? client_state_machine(current, flags) : server_state_machine(current, flags);
}

bool TcpStateMachine::should_enter_time_wait(TCPState current, uint8_t flags, bool is_client) {
    if (is_client) {
        return (current == TCPState::FIN_WAIT_1 && ((flags & TH_FIN) && (flags & TH_ACK))) ||
               (current == TCPState::FIN_WAIT_2 && (flags & TH_FIN)) ||
               (current == TCPState::CLOSING && (flags & TH_ACK));
    } else {
        return (current == TCPState::FIN_WAIT_1 && ((flags & TH_FIN) && (flags & TH_ACK))) ||
               (current == TCPState::FIN_WAIT_2 && (flags & TH_FIN)) ||
               (current == TCPState::CLOSING && (flags & TH_ACK));
    }
}

bool TcpStateMachine::should_clean_up(const ConnState& client_state, const ConnState& server_state, 
                                    const std::chrono::steady_clock::time_point& last_update) const     {
    auto now = std::chrono::steady_clock::now();

    // 1. If both sides have definitively reached CLOSED state
    if (client_state.state == TCPState::CLOSED && server_state.state == TCPState::CLOSED) {
        return true;
    }

    // 2. Handle TIME_WAIT timeout
    bool client_timed_out = false;
    if (client_state.state == TCPState::TIME_WAIT && client_state.time_wait_entry_time.has_value()) {
        client_timed_out = (now - client_state.time_wait_entry_time.value()) >= TIME_WAIT_DURATION;
    }

    bool server_timed_out = false;
    if (server_state.state == TCPState::TIME_WAIT && server_state.time_wait_entry_time.has_value()) {
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