#ifndef TLS12_STATE_MACHINE_HPP
#define TLS12_STATE_MACHINE_HPP

#include "definitions/tls_types.hpp"
#include "definitions/direction.hpp"
#include <functional>
#include <string>

class TLS12StateMachine {
public:
    explicit TLS12StateMachine(std::function<void(const std::string&)> log_helper);

    bool process_handshake(Direction dir, TLSHandshakeType msg_type);
    bool process_change_cipher_spec(Direction dir);
    
    TLS12State get_state() const { return state_; }
    void reset();

private:
    bool validate_transition(TLS12State new_state);

    // Update state if transition is valid
    void update_state(TLS12State new_state);

    TLS12State state_ = TLS12State::INIT;
    std::function<void(const std::string&)> log_helper_;
};

#endif // TLS12_STATE_MACHINE_HPP 