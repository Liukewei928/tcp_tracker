#include "tcp/tcp_state.hpp"

std::string state_to_string(tcp_state state) {
    switch (state) {
        case tcp_state::closed: return "closed";
        case tcp_state::syn_sent: return "syn_sent";
        case tcp_state::syn_received: return "syn_received";
        case tcp_state::established: return "established";
        case tcp_state::fin_wait_1: return "fin_wait_1";
        case tcp_state::fin_wait_2: return "fin_wait_2";
        case tcp_state::close_wait: return "close_wait";
        case tcp_state::last_ack: return "last_ack";
        case tcp_state::time_wait: return "time_wait";
        default: return "unknown";
    }
}
