#include "tcp/connection.hpp"
#include "tcp_def/ip_tcp_header.hpp"
#include "log/state_log_entry.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <sstream>

Connection::Connection(const ConnectionKey& key, int id, bool debug_mode, Reassebly::DataCallback data_callback)
    : key_(key), id_(id), last_update_(std::chrono::steady_clock::now()), state_log_("state.log", debug_mode), debug_mode_(debug_mode) {
	last_update_ = std::chrono::steady_clock::now();
    // Client starts by initiating connection -> SYN_SENT
    // Server starts by listening -> LISTEN
    client_state_.state = tcp_state::syn_sent; // More accurate starting point if created on first SYN
    server_state_.state = tcp_state::listen;
    client_state_.start_time = last_update_;
    server_state_.start_time = last_update_;
    client_state_.prev_state = tcp_state::closed; // Indicate transition from non-existence
    server_state_.prev_state = tcp_state::closed; // Indicate transition from non-existence

    // Initialize reassembly objects for both directions
    client_reassembly_ = std::make_unique<Reassebly>(key, ReassemblyDirection::CLIENT_TO_SERVER, debug_mode, data_callback);
    server_reassembly_ = std::make_unique<Reassebly>(!key, ReassemblyDirection::SERVER_TO_CLIENT, debug_mode, data_callback);

    // Log initial state
    std::string initial_info = "Initial State: cli:" + state_to_string(client_state_.state) +
                               " srv:" + state_to_string(server_state_.state);
    state_log_.log(std::make_shared<StateLogEntry>(key_, initial_info));
}

Connection::~Connection() {
    state_log_.flush(); // Ensure logs are written on destruction
}

// Helper to convert flags to string for logging
std::string flags_to_string(uint8_t flags) {
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


tcp_state client_state_machine(tcp_state current, uint8_t flags) {
    if (flags & TH_RST) return tcp_state::closed;
    switch (current) {
        case tcp_state::closed: break; // No transition based on received packets
        case tcp_state::listen: break; // Client doesn't listen
        case tcp_state::syn_sent:
            if ((flags & TH_SYN) && (flags & TH_ACK)) return tcp_state::established; // Normal SYN+ACK
            if (flags & TH_SYN) return tcp_state::syn_received; // Simultaneous open
            break;
        case tcp_state::syn_received: // Client in simultaneous open
            if (flags & TH_ACK) return tcp_state::established;
            if (flags & TH_FIN) return tcp_state::close_wait; // Abnormal
            break;
        case tcp_state::established:
            if (flags & TH_FIN) return tcp_state::close_wait; // Server initiates close
            break;
        case tcp_state::fin_wait_1: // Client closed first
            if ((flags & TH_FIN) && (flags & TH_ACK)) return tcp_state::time_wait; // FIN+ACK
            if (flags & TH_ACK) return tcp_state::fin_wait_2; // ACK only
            if (flags & TH_FIN) return tcp_state::closing;   // FIN only (Simultaneous close race)
            break;
        case tcp_state::fin_wait_2: // Client got ACK for FIN, waiting for server FIN
            if (flags & TH_FIN) return tcp_state::time_wait;
            break;
        case tcp_state::close_wait: break; // Waiting for local app close, no change on packet
        case tcp_state::closing: // Simultaneous close state
            if (flags & TH_ACK) return tcp_state::time_wait; // Got ACK for our FIN
            break;
        case tcp_state::last_ack: // Client was in CLOSE_WAIT, sent FIN
            if (flags & TH_ACK) return tcp_state::closed; // Final ACK received
            break;
        case tcp_state::time_wait: break; // Stays in TIME_WAIT until timeout
        default: break;
	}
	return current;
}


// --- Add Verbose Logging INSIDE the state determination functions ---
tcp_state Connection::determine_new_client_state(tcp_state current, uint8_t flags) {    
	if (debug_mode_) { // Only log if debug enabled
        std::cout << "[DEBUG C] Current: " << state_to_string(current)
                  << ", Rcvd Flags: " << flags_to_string(flags) << " (" << static_cast<int>(flags) << ")" << std::endl;
    }

    tcp_state determined_state = client_state_machine(current, flags);
 	
	// Calculate the state first
     if (debug_mode_) {
        if (determined_state != current) {
             std::cout << "[DEBUG C] Determined transition: " << state_to_string(current) << " -> " << state_to_string(determined_state) << std::endl;
        } else {
             std::cout << "[DEBUG C] No state change determined." << std::endl;
        }
     }
    return determined_state;
}


tcp_state server_state_machine(tcp_state current, uint8_t flags) {
    if (flags & TH_RST) return tcp_state::closed;
    switch (current) {
        case tcp_state::closed: break; // Should start in LISTEN
        case tcp_state::listen:
            if ((flags & TH_SYN) && !(flags & TH_ACK)) return tcp_state::syn_received; // Got SYN
            break;
        case tcp_state::syn_sent: break; // Server doesn't usually do SYN_SENT
        case tcp_state::syn_received: // Server sent SYN+ACK
            if (flags & TH_ACK) return tcp_state::established; // Got final ACK
            if (flags & TH_FIN) return tcp_state::close_wait; // Abnormal: FIN instead of ACK
            break;
        case tcp_state::established:
            if (flags & TH_FIN) return tcp_state::close_wait; // Client initiates close
            break;
        case tcp_state::fin_wait_1: // Server closed first
            if ((flags & TH_FIN) && (flags & TH_ACK)) return tcp_state::time_wait; // FIN+ACK
            if (flags & TH_ACK) return tcp_state::fin_wait_2; // ACK only
            if (flags & TH_FIN) return tcp_state::closing; // FIN only (Simultaneous close race)
            break;
        case tcp_state::fin_wait_2: // Server got ACK for FIN, waiting for client FIN
            if (flags & TH_FIN) return tcp_state::time_wait;
            break;
        case tcp_state::close_wait: break; // Waiting for local app close, no change on packet
        case tcp_state::closing: // Simultaneous close state
            if (flags & TH_ACK) return tcp_state::time_wait; // Got ACK for our FIN
            break;
        case tcp_state::last_ack: // Server was in CLOSE_WAIT, sent FIN
            if (flags & TH_ACK) return tcp_state::closed; // Final ACK received
            break;
        case tcp_state::time_wait: break; // Stays in TIME_WAIT until timeout
        default: break;
    }
    return current;
}


// --- Add similar verbose logging inside determine_new_server_state ---
tcp_state Connection::determine_new_server_state(tcp_state current, uint8_t flags) {
     if (debug_mode_) {
        std::cout << "[DEBUG S] Current: " << state_to_string(current)
                  << ", Rcvd Flags: " << flags_to_string(flags) << " (" << static_cast<int>(flags) << ")" << std::endl;
     }

     tcp_state determined_state = server_state_machine(current, flags);

     if (debug_mode_) {
        if (determined_state != current) {
             std::cout << "[DEBUG S] Determined transition: " << state_to_string(current) << " -> " << state_to_string(determined_state) << std::endl;
        } else {
             std::cout << "[DEBUG S] No state change determined." << std::endl;
        }
     }
    return determined_state;
}


// --- Adjust State Update Logging (as before, ensure correct key) ---
void Connection::update_client_state(uint8_t flags) {
    tcp_state current_state = client_state_.state;
    tcp_state new_state = determine_new_client_state(current_state, flags);

    if (new_state != current_state) {
        auto timestamp = std::chrono::steady_clock::now();
        // Log shows transition *before* updating state member
        std::string change_info = "Trigger: S->C flags(" + flags_to_string(flags) + ") | " + // Show trigger
                                  "cli: " + state_to_string(current_state) + " -> " + state_to_string(new_state) +
                                  " | srv_ctx: " + state_to_string(server_state_.state);
        state_log_.log(std::make_shared<StateLogEntry>(!key_, change_info)); // Use !key_

        // Update state members AFTER logging
        client_state_.prev_state = current_state;
        client_state_.state = new_state;
        client_state_.start_time = timestamp;
        last_update_ = timestamp;
        // ... (time_wait logic) ...
    } else {
        last_update_ = std::chrono::steady_clock::now();
    }
}

// --- Adjust update_server_state similarly ---
void Connection::update_server_state(uint8_t flags) {
     tcp_state current_state = server_state_.state;
     tcp_state new_state = determine_new_server_state(current_state, flags);

     if (new_state != current_state) {
        auto timestamp = std::chrono::steady_clock::now();
        // Log shows transition *before* updating state member
        std::string change_info = "Trigger: C->S flags(" + flags_to_string(flags) + ") | " + // Show trigger
                                  "srv: " + state_to_string(current_state) + " -> " + state_to_string(new_state) +
                                  " | cli_ctx: " + state_to_string(client_state_.state);
        state_log_.log(std::make_shared<StateLogEntry>(key_, change_info)); // Use key_

        // Update state members AFTER logging
        server_state_.prev_state = current_state;
        server_state_.state = new_state;
        server_state_.start_time = timestamp;
        last_update_ = timestamp;
        // ... (time_wait logic) ...
     } else {
        last_update_ = std::chrono::steady_clock::now();
     }
}


// Checks if the packet source IP matches the client IP stored in the key
bool Connection::is_from_client(const std::string& pkt_src_ip) const {
	// key_.src_ip is always the client IP
	return key_.src_ip == pkt_src_ip;
}

bool Connection::should_clean_up() const {
    auto now = std::chrono::steady_clock::now();

    // 1. If both sides have definitively reached CLOSED state
    if (client_state_.state == tcp_state::closed && server_state_.state == tcp_state::closed) {
        // Allow a brief moment maybe? Or cleanup immediately.
        // Immediate cleanup is fine if CLOSED means fully terminated.
        return true;
    }

    // 2. Handle TIME_WAIT timeout
    bool client_timed_out = false;
    if (client_state_.state == tcp_state::time_wait && client_state_.time_wait_entry_time.has_value()) {
        client_timed_out = (now - client_state_.time_wait_entry_time.value()) >= TIME_WAIT_DURATION;
    }

    bool server_timed_out = false;
    if (server_state_.state == tcp_state::time_wait && server_state_.time_wait_entry_time.has_value()) {
        server_timed_out = (now - server_state_.time_wait_entry_time.value()) >= TIME_WAIT_DURATION;
    }

    // Cleanup if *either* side's TIME_WAIT has expired
    // (Technically only one side enters TIME_WAIT typically, but handle both defensively)
    if (client_timed_out || server_timed_out) {
        return true;
    }

    // 3. Add other conditions? (e.g., general inactivity timeout for non-closed states?)
    // For now, focus on CLOSED and TIME_WAIT expiration.
    // Example: Cleanup after long inactivity even if established?
    // constexpr std::chrono::seconds MAX_INACTIVITY(300); // 5 minutes
    // if (std::chrono::duration_cast<std::chrono::seconds>(now - last_update_) > MAX_INACTIVITY) {
    //     return true; // Add if needed
    // }


    return false; // Otherwise, keep the connection tracked
}

// Generates log string showing current states and potentially duration in ESTABLISHED
std::string Connection::get_state_change_info(std::chrono::steady_clock::time_point now) const {
    std::ostringstream oss;
    oss << "cli:" << state_to_string(client_state_.state);
    // Log duration if LEAVING established state
    if (client_state_.prev_state == tcp_state::established && client_state_.state != tcp_state::established) {
        auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(now - client_state_.start_time).count();
        double duration_s = duration_us / 1000000.0;
        oss << "(" << std::fixed << std::setprecision(3) << duration_s << " s)";
    }
    oss << " srv:" << state_to_string(server_state_.state);
    // Log duration if LEAVING established state
    if (server_state_.prev_state == tcp_state::established && server_state_.state != tcp_state::established) {
        auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(now - server_state_.start_time).count();
        double duration_s = duration_us / 1000000.0;
        oss << "(" << std::fixed << std::setprecision(3) << duration_s << " s)";
    }
    return oss.str();
}

std::string Connection::state_to_string(tcp_state s) const {
    switch(s) {
        case tcp_state::closed: return "CLOSED";
        case tcp_state::listen: return "LISTEN";
        case tcp_state::syn_sent: return "SYN_SENT";
        case tcp_state::syn_received: return "SYN_RECEIVED";
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

void Connection::process_payload(bool is_from_client, uint32_t seq, const uint8_t* payload, size_t payload_len, uint8_t flags) {
    // Handle sequence number initialization on SYN
    if (flags & TH_SYN) {
        handle_syn_sequence(is_from_client, seq);
    }

    // Process the payload through appropriate reassembly object
    if (is_from_client) {
        client_reassembly_->process(seq, payload, payload_len, flags & TH_SYN, flags & TH_FIN);
        if (flags & TH_FIN) {
            client_reassembly_->fin_received();
        }
    } else {
        server_reassembly_->process(seq, payload, payload_len, flags & TH_SYN, flags & TH_FIN);
        if (flags & TH_FIN) {
            server_reassembly_->fin_received();
        }
    }

    // Handle connection reset
    if (flags & TH_RST) {
        client_reassembly_->reset();
        server_reassembly_->reset();
    }
}
