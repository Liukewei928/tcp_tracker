#ifndef TCP_STATE_HPP
#define TCP_STATE_HPP

#include <string>

enum class tcp_state {
    closed,
    listen,
	syn_sent,
    syn_received,
    established,
    fin_wait_1,
    fin_wait_2,
    close_wait,
	closing,
    last_ack,
    time_wait
};

#endif // TCP_STATE_HPP
