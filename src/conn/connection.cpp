#include "conn/connection.hpp"
#include "definations/ip_tcp_header.hpp"
#include "log/conn_log_entry.hpp"
#include "interfaces/protocol_analyzer.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <sstream>

Connection::Connection(const ConnectionKey& key, int id, bool debug_mode)
    : key_(key), id_(id), last_update_(std::chrono::steady_clock::now()), 
    state_log_("state.log", debug_mode), debug_mode_(debug_mode) {
    // Client starts by initiating connection -> SYN_SENT
    // Server starts by listening -> LISTEN
    client_state_.state = tcp_state::syn_sent; // More accurate starting point if created on first SYN
    server_state_.state = tcp_state::listen;
    client_state_.start_time = last_update_;
    server_state_.start_time = last_update_;
    client_state_.prev_state = tcp_state::closed; // Indicate transition from non-existence
    server_state_.prev_state = tcp_state::closed; // Indicate transition from non-existence

    // Initialize reassembly objects for both directions
    client_reassembly_ = std::make_unique<Reassembly>(key, ReassemblyDirection::CLIENT_TO_SERVER, debug_mode);
    server_reassembly_ = std::make_unique<Reassembly>(!key, ReassemblyDirection::SERVER_TO_CLIENT, debug_mode);

    // Log initial state
    std::string initial_info = "Initial State: cli:" + TcpStateMachine::state_to_string(client_state_.state) +
                               " srv:" + TcpStateMachine::state_to_string(server_state_.state);
    state_log_.log(std::make_shared<ConnLogEntry>(key_, initial_info));
}

Connection::~Connection() {
    state_log_.flush(); // Ensure logs are written on destruction
}

void Connection::add_analyzer(std::shared_ptr<IProtocolAnalyzer> analyzer) {
    client_reassembly_->add_analyzer(analyzer);
    server_reassembly_->add_analyzer(analyzer);
}

void Connection::update_client_state(uint8_t flags) {
    tcp_state current_state = client_state_.state;
    tcp_state new_state = state_machine_.determine_new_state(current_state, flags, true);

    if (new_state != current_state) {
        auto timestamp = std::chrono::steady_clock::now();
        // Log shows transition *before* updating state member
        std::string change_info = "Trigger: S->C flags(" + TcpStateMachine::flags_to_string(flags) + ") | " + // Show trigger
                                  "cli: " + TcpStateMachine::state_to_string(current_state) + " -> " + TcpStateMachine::state_to_string(new_state) +
                                  " | srv_ctx: " + TcpStateMachine::state_to_string(server_state_.state);
        state_log_.log(std::make_shared<ConnLogEntry>(!key_, change_info)); // Use !key_

        // Update state members AFTER logging
        client_state_.prev_state = current_state;
        client_state_.state = new_state;
        client_state_.start_time = timestamp;
        last_update_ = timestamp;

        // Set time_wait_entry_time when entering TIME_WAIT state
        if (new_state == tcp_state::time_wait) {
            client_state_.time_wait_entry_time = timestamp;
        }
    } else {
        last_update_ = std::chrono::steady_clock::now();
    }
}

void Connection::update_server_state(uint8_t flags) {
    tcp_state current_state = server_state_.state;
    tcp_state new_state = state_machine_.determine_new_state(current_state, flags, false);

    if (new_state != current_state) {
        auto timestamp = std::chrono::steady_clock::now();
        // Log shows transition *before* updating state member
        std::string change_info = "Trigger: C->S flags(" + TcpStateMachine::flags_to_string(flags) + ") | " + // Show trigger
                                  "srv: " + TcpStateMachine::state_to_string(current_state) + " -> " + TcpStateMachine::state_to_string(new_state) +
                                  " | cli_ctx: " + TcpStateMachine::state_to_string(client_state_.state);
        state_log_.log(std::make_shared<ConnLogEntry>(key_, change_info)); // Use key_

        // Update state members AFTER logging
        server_state_.prev_state = current_state;
        server_state_.state = new_state;
        server_state_.start_time = timestamp;
        last_update_ = timestamp;

        // Set time_wait_entry_time when entering TIME_WAIT state
        if (new_state == tcp_state::time_wait) {
            server_state_.time_wait_entry_time = timestamp;
        }
    } else {
        last_update_ = std::chrono::steady_clock::now();
    }
}

bool Connection::should_clean_up() const {
    return state_machine_.should_clean_up(client_state_, server_state_, last_update_);
}

void Connection::handle_syn_sequence(bool is_from_client, uint32_t seq) {
    if (is_from_client) {
        if (client_state_.state == tcp_state::syn_sent) {
            client_reassembly_->set_initial_seq(seq + 1); // ISN + 1 for data
        }
    } else {
        if (server_state_.state == tcp_state::syn_received) {
            server_reassembly_->set_initial_seq(seq + 1); // ISN + 1 for data
        }
    }
}

void Connection::handle_reassembly(bool is_from_client, uint32_t seq, const uint8_t* payload, size_t payload_len, uint8_t flags) {
    if (is_from_client) {
        client_reassembly_->process(seq, payload, payload_len, flags & TH_SYN, flags & TH_FIN);
    } else {
        server_reassembly_->process(seq, payload, payload_len, flags & TH_SYN, flags & TH_FIN);
    }
}

void Connection::handle_fin(bool is_from_client) {
    if (is_from_client) {
        client_reassembly_->fin_received();
    } else {
        server_reassembly_->fin_received();
    }
}

void Connection::handle_rst() {
    client_reassembly_->reset();
    server_reassembly_->reset();
}

void Connection::process_payload(bool is_from_client, uint32_t seq, const uint8_t* payload, size_t payload_len, uint8_t flags) {
    // Handle sequence number initialization on SYN
    if (flags & TH_SYN) {
        handle_syn_sequence(is_from_client, seq);
    }

    // Process the payload through appropriate reassembly object
    handle_reassembly(is_from_client, seq, payload, payload_len, flags);

    // Handle FIN
    if (flags & TH_FIN) {
        handle_fin(is_from_client);
    }

    // Handle connection reset
    if (flags & TH_RST) {
        handle_rst();
    }
}
