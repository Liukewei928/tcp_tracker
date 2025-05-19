#include "tls/tls12_state_machine.hpp"
#include <sstream>

TLS12StateMachine::TLS12StateMachine(std::function<void(const std::string&)> log_helper)
    : state_(TLS12State::INIT), log_helper_(std::move(log_helper)) {
}

bool TLS12StateMachine::process_handshake(Direction dir, TLSHandshakeType msg_type) {
    TLS12State new_state = state_;
    bool valid_transition = false;

    if ((state_ == TLS12State::CHANGE_CIPHER_SPEC_SENT && dir == Direction::CLIENT_TO_SERVER) || 
        (state_ == TLS12State::CHANGE_CIPHER_SPEC_RECEIVED && dir == Direction::SERVER_TO_CLIENT)) {
        log_helper_("Processing handshake with encrypted data after ChangeCipherSpec");
        return process_change_cipher_spec(dir);
    }

    // Log the received message
    std::ostringstream oss;
    oss << "Processing handshake: " << static_cast<int>(msg_type) 
        << " (" << get_tls_handshake_type_name(msg_type) << ")";
    log_helper_(oss.str());

    // Handle state transitions based on current state and message type
    switch (state_) {
        case TLS12State::INIT:
            if (dir == Direction::CLIENT_TO_SERVER && msg_type == TLSHandshakeType::CLIENT_HELLO) {
                new_state = TLS12State::CLIENT_HELLO_SENT;
                valid_transition = true;
            }
            break;

        case TLS12State::CLIENT_HELLO_SENT:
            if (dir == Direction::SERVER_TO_CLIENT) {
                switch (msg_type) {
                    case TLSHandshakeType::SERVER_HELLO:
                        new_state = TLS12State::SERVER_HELLO_RECEIVED;
                        valid_transition = true;
                        break;
                    default:
                        break;
                }
            }
            break;

        case TLS12State::SERVER_HELLO_RECEIVED:
            if (dir == Direction::SERVER_TO_CLIENT) {
                switch (msg_type) {
                    case TLSHandshakeType::CERTIFICATE:
                        new_state = TLS12State::CERTIFICATE_RECEIVED;
                        valid_transition = true;
                        break;
                    case TLSHandshakeType::SERVER_KEY_EXCHANGE:
                        new_state = TLS12State::SERVER_KEY_EXCHANGE_RECEIVED;
                        valid_transition = true;
                        break;
                    case TLSHandshakeType::CERTIFICATE_REQUEST:
                        new_state = TLS12State::CERTIFICATE_REQUEST_RECEIVED;
                        valid_transition = true;
                        break;
                    case TLSHandshakeType::SERVER_HELLO_DONE:
                        new_state = TLS12State::SERVER_HELLO_DONE_RECEIVED;
                        valid_transition = true;
                        break;
                    default:
                        break;
                }
            }
            break;

        case TLS12State::CERTIFICATE_RECEIVED:
            if (dir == Direction::SERVER_TO_CLIENT) {
                switch (msg_type) {
                    case TLSHandshakeType::SERVER_KEY_EXCHANGE:
                        new_state = TLS12State::SERVER_KEY_EXCHANGE_RECEIVED;
                        valid_transition = true;
                        break;
                    case TLSHandshakeType::CERTIFICATE_REQUEST:
                        new_state = TLS12State::CERTIFICATE_REQUEST_RECEIVED;
                        valid_transition = true;
                        break;
                    case TLSHandshakeType::SERVER_HELLO_DONE:
                        new_state = TLS12State::SERVER_HELLO_DONE_RECEIVED;
                        valid_transition = true;
                        break;
                    default:
                        break;
                }
            }
            break;

        case TLS12State::SERVER_KEY_EXCHANGE_RECEIVED:
            if (dir == Direction::SERVER_TO_CLIENT) {
                switch (msg_type) {
                    case TLSHandshakeType::CERTIFICATE_REQUEST:
                        new_state = TLS12State::CERTIFICATE_REQUEST_RECEIVED;
                        valid_transition = true;
                        break;
                    case TLSHandshakeType::SERVER_HELLO_DONE:
                        new_state = TLS12State::SERVER_HELLO_DONE_RECEIVED;
                        valid_transition = true;
                        break;
                    default:
                        break;
                }
            }
            break;

        case TLS12State::CERTIFICATE_REQUEST_RECEIVED:
            if (dir == Direction::SERVER_TO_CLIENT && msg_type == TLSHandshakeType::SERVER_HELLO_DONE) {
                new_state = TLS12State::SERVER_HELLO_DONE_RECEIVED;
                valid_transition = true;
            }
            break;

        case TLS12State::SERVER_HELLO_DONE_RECEIVED:
            if (dir == Direction::CLIENT_TO_SERVER) {
                switch (msg_type) {
                    case TLSHandshakeType::CERTIFICATE:
                        new_state = TLS12State::CERTIFICATE_SENT;
                        valid_transition = true;
                        break;
                    case TLSHandshakeType::CLIENT_KEY_EXCHANGE:
                        new_state = TLS12State::CLIENT_KEY_EXCHANGE_SENT;
                        valid_transition = true;
                        break;
                    default:
                        break;
                }
            }
            break;

        case TLS12State::CERTIFICATE_SENT:
            if (dir == Direction::CLIENT_TO_SERVER) {
                switch (msg_type) {
                    case TLSHandshakeType::CERTIFICATE_VERIFY:
                        new_state = TLS12State::CERTIFICATE_VERIFY_SENT;
                        valid_transition = true;
                        break;
                    case TLSHandshakeType::CLIENT_KEY_EXCHANGE:
                        new_state = TLS12State::CLIENT_KEY_EXCHANGE_SENT;
                        valid_transition = true;
                        break;
                    default:
                        break;
                }
            }
            break;

        case TLS12State::CERTIFICATE_VERIFY_SENT:
            if (dir == Direction::CLIENT_TO_SERVER && msg_type == TLSHandshakeType::CLIENT_KEY_EXCHANGE) {
                new_state = TLS12State::CLIENT_KEY_EXCHANGE_SENT;
                valid_transition = true;
            }
            break;

        case TLS12State::CLIENT_KEY_EXCHANGE_SENT:
            if (dir == Direction::CLIENT_TO_SERVER) {
                switch (msg_type) {
                    case TLSHandshakeType::FINISHED:
                        new_state = TLS12State::FINISHED_SENT;
                        valid_transition = true;
                        break;
                    default:
                        break;
                }
            }
            break;

        case TLS12State::FINISHED_SENT:
            if (dir == Direction::SERVER_TO_CLIENT && msg_type == TLSHandshakeType::FINISHED) {
                new_state = TLS12State::FINISHED_RECEIVED;
                valid_transition = true;
            }
            if (dir == Direction::SERVER_TO_CLIENT && msg_type == TLSHandshakeType::NEW_SESSION_TICKET) {
                log_helper_("Received optional NewSessionTicket");
                valid_transition = true;
                // Remain in the same state
            }
            break;

        case TLS12State::FINISHED_RECEIVED:
            // No more handshake messages expected
            break;

        case TLS12State::HANDSHAKE_COMPLETE:
            // Handshake is complete, no more state changes
            break;

        case TLS12State::ERROR:
            // In error state, no valid transitions
            break;
    }

    if (!valid_transition) {
        std::ostringstream err_oss;
        err_oss << "Invalid state transition: " << static_cast<int>(state_) 
                << " -> " << static_cast<int>(msg_type) 
                << " (" << get_tls_handshake_type_name(msg_type) << ")";
        log_helper_(err_oss.str());
        new_state = TLS12State::ERROR;
    }

    if (validate_transition(new_state)) {
        update_state(new_state);
        return true;
    }
    return false;
}

bool TLS12StateMachine::process_change_cipher_spec(Direction dir) {
    TLS12State new_state = state_;
    bool valid_transition = false;

    log_helper_("Processing ChangeCipherSpec message");

    switch (state_) {
        case TLS12State::FINISHED_SENT:
            if (dir == Direction::SERVER_TO_CLIENT) {
                new_state = TLS12State::CHANGE_CIPHER_SPEC_RECEIVED;
                valid_transition = true;
            }
            break;

        case TLS12State::CLIENT_KEY_EXCHANGE_SENT:
            if (dir == Direction::CLIENT_TO_SERVER) {
                new_state = TLS12State::CHANGE_CIPHER_SPEC_SENT;
                valid_transition = true;
            }
            break;

        case TLS12State::CHANGE_CIPHER_SPEC_SENT:
            if (dir == Direction::CLIENT_TO_SERVER) {
                new_state = TLS12State::FINISHED_SENT;
                valid_transition = true;
            }
            break;

        case TLS12State::CHANGE_CIPHER_SPEC_RECEIVED:
            if (dir == Direction::SERVER_TO_CLIENT) {
                new_state = TLS12State::FINISHED_RECEIVED;
                valid_transition = true;
            }
            break;

        case TLS12State::FINISHED_RECEIVED:
            new_state = TLS12State::HANDSHAKE_COMPLETE;
            valid_transition = true;
            break;

        default:
            break;
    }

    if (!valid_transition) {
        std::ostringstream err_oss;
        err_oss << "Invalid ChangeCipherSpec in state: " << static_cast<int>(state_);
        log_helper_(err_oss.str());
        new_state = TLS12State::ERROR;
    }

    if (validate_transition(new_state)) {
        update_state(new_state);
        return true;
    }
    return false;
}

void TLS12StateMachine::reset() {
    state_ = TLS12State::INIT;
    log_helper_("State machine reset to INIT");
}

bool TLS12StateMachine::validate_transition(TLS12State new_state) {
    // Add any additional validation logic here if needed
    return true;
}

void TLS12StateMachine::update_state(TLS12State new_state) {
    std::ostringstream oss;
    oss << "State transition: " << static_cast<int>(state_) 
        << " (" << get_tls12_state_name(state_) << ")"
        << " -> " << static_cast<int>(new_state) << " ("
        << get_tls12_state_name(new_state) << ")";
    log_helper_(oss.str());
    state_ = new_state;
} 
