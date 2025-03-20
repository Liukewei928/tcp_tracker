#ifndef TCP_STATE_HPP
#define TCP_STATE_HPP

#include <string>

enum class tcp_state {
    closed,
    syn_sent,
    syn_received,
    established,
    fin_wait_1,
    fin_wait_2,
    close_wait,
    last_ack,
    time_wait
};

std::string state_to_string(tcp_state state);

#endif // TCP_STATE_HPP
