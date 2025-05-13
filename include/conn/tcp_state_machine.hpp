#ifndef TCP_STATE_MACHINE_HPP
#define TCP_STATE_MACHINE_HPP

#include <string>
#include <chrono>

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

struct State {
    tcp_state state = tcp_state::closed;
    tcp_state prev_state = tcp_state::closed;
    std::chrono::steady_clock::time_point start_time;
    std::optional<std::chrono::steady_clock::time_point> time_wait_entry_time;
};

class TcpStateMachine {
public:
    TcpStateMachine() = default;

    // Instance methods for state management
    tcp_state determine_new_state(tcp_state current, uint8_t flags, bool is_client);
    bool should_enter_time_wait(tcp_state current, uint8_t flags, bool is_client);
    bool should_clean_up(const State& client_state, const State& server_state, 
                        const std::chrono::steady_clock::time_point& last_update) const;

    // Static utility methods that don't need state
    static std::string state_to_string(tcp_state s);
    static std::string flags_to_string(uint8_t flags);

private:
    tcp_state client_state_machine(tcp_state current, uint8_t flags);
    tcp_state server_state_machine(tcp_state current, uint8_t flags);

    static constexpr std::chrono::seconds TIME_WAIT_DURATION{60};
    static constexpr std::chrono::seconds MAX_INACTIVITY{60};
};

#endif // TCP_STATE_MACHINE_HPP
