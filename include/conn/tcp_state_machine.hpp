#ifndef TCP_STATE_MACHINE_HPP
#define TCP_STATE_MACHINE_HPP

#include <string>
#include <chrono>

enum class TCPState {
    CLOSED,
    LISTEN,
	SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2, 
    CLOSE_WAIT,
	CLOSING,
    LAST_ACK,
    TIME_WAIT
};

struct ConnState {
    TCPState state = TCPState::CLOSED;
    TCPState prev_state = TCPState::CLOSED;
    std::chrono::steady_clock::time_point start_time;
    std::optional<std::chrono::steady_clock::time_point> time_wait_entry_time;
};

class TcpStateMachine {
public:
    TcpStateMachine() = default;

    // Instance methods for state management
    TCPState determine_new_state(TCPState current, uint8_t flags, bool is_client);
    bool should_enter_time_wait(TCPState current, uint8_t flags, bool is_client);
    bool should_clean_up(const ConnState& client_state, const ConnState& server_state, 
                        const std::chrono::steady_clock::time_point& last_update) const;

    // Static utility methods that don't need state
    static std::string state_to_string(TCPState s);
    static std::string flags_to_string(uint8_t flags);

private:
    TCPState client_state_machine(TCPState current, uint8_t flags);
    TCPState server_state_machine(TCPState current, uint8_t flags);

    static constexpr std::chrono::seconds TIME_WAIT_DURATION{60};
    static constexpr std::chrono::seconds MAX_INACTIVITY{60};
};

#endif // TCP_STATE_MACHINE_HPP
