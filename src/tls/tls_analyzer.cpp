#include "tls/tls_analyzer.hpp"
#include "log/conn_log_entry.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

TLSAnalyzer::TLSAnalyzer(const ConnectionKey& key)
    : key_(key), state_(TLSState::INIT) { }

TLSAnalyzer::~TLSAnalyzer() {
    tls_log_.flush();
}

void TLSAnalyzer::on_data(ReassemblyDirection dir, const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << "on_data - " << (dir == ReassemblyDirection::CLIENT_TO_SERVER ? "Client->Server" : "Server->Client")
        << " (" << len << " bytes)";
    tls_log_.log(std::make_shared<ConnLogEntry>(key_, ss.str()));
    std::cout << ss.str() << std::endl;

    // Add data to appropriate buffer
    auto& buffer = (dir == ReassemblyDirection::CLIENT_TO_SERVER) ? 
                   client_buffer_ : server_buffer_;
    
    buffer.add_data(data, len);

    // Process complete records
    TLSContentType type;
    std::vector<uint8_t> fragment;
    while (buffer.try_extract_record(type, fragment)) {

        std::stringstream ss;
        ss << "Extracted record of type: " << static_cast<int>(type)
           << " (length: " << fragment.size() << ")";
        tls_log_.log(std::make_shared<ConnLogEntry>(key_, ss.str()));
        std::cout << ss.str() << std::endl;

        handle_record(dir, type, fragment);
    }
}

void TLSAnalyzer::handle_record(ReassemblyDirection dir, TLSContentType type,
                               const std::vector<uint8_t>& fragment) {
    switch (type) {
        case TLSContentType::HANDSHAKE:
            handle_handshake(dir, fragment);
            break;
            
        case TLSContentType::ALERT:
            handle_alert(dir, fragment);
            break;
            
        case TLSContentType::CHANGE_CIPHER_SPEC:
            handle_change_cipher_spec(dir);
            break;
            
        case TLSContentType::APPLICATION_DATA:
            // Ignore application data in this implementation
            break;
    }
}

void TLSAnalyzer::handle_handshake(ReassemblyDirection dir, const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return;
    }

    TLSHandshakeType msg_type = static_cast<TLSHandshakeType>(data[0]);
    
    std::stringstream ss;
    ss << "handle_handshake - message type: " << static_cast<int>(msg_type);
    tls_log_.log(std::make_shared<ConnLogEntry>(key_, ss.str()));
    std::cout << ss.str() << std::endl;
    
    switch (msg_type) {
        case TLSHandshakeType::CLIENT_HELLO:
            if (state_ == TLSState::INIT && 
                dir == ReassemblyDirection::CLIENT_TO_SERVER) {
                update_state(TLSState::HANDSHAKE_STARTED);
            }
            break;
            
        case TLSHandshakeType::SERVER_HELLO:
            if (state_ == TLSState::HANDSHAKE_STARTED && 
                dir == ReassemblyDirection::SERVER_TO_CLIENT) {
                update_state(TLSState::NEGOTIATING);
            }
            break;
            
        case TLSHandshakeType::FINISHED:
            if (state_ == TLSState::NEGOTIATING) {
                update_state(TLSState::HANDSHAKE_DONE);
            }
            break;
            
        default:
            // Process other handshake messages based on state
            break;
    }
}

void TLSAnalyzer::handle_alert(ReassemblyDirection dir, const std::vector<uint8_t>& data) {
    if (data.size() < 2) {
        return;  // Alert message must be at least 2 bytes
    }
    
    // uint8_t level = data[0];    // Alert level
    // uint8_t description = data[1]; // Alert description
    
    // For now, any alert moves us to ERROR state
    update_state(TLSState::ERROR);
}

void TLSAnalyzer::handle_change_cipher_spec(ReassemblyDirection dir) {
    // Change Cipher Spec is usually received before Finished
    if (state_ == TLSState::NEGOTIATING) {
        // Continue in NEGOTIATING state, waiting for Finished
    }
}

void TLSAnalyzer::update_state(TLSState new_state) {
    // Validate state transition
    bool valid_transition = false;
    
    switch (state_) {
        case TLSState::INIT:
            valid_transition = (new_state == TLSState::HANDSHAKE_STARTED ||
                              new_state == TLSState::ERROR);
            break;
            
        case TLSState::HANDSHAKE_STARTED:
            valid_transition = (new_state == TLSState::NEGOTIATING ||
                              new_state == TLSState::ERROR);
            break;
            
        case TLSState::NEGOTIATING:
            valid_transition = (new_state == TLSState::HANDSHAKE_DONE ||
                              new_state == TLSState::ERROR);
            break;
            
        case TLSState::HANDSHAKE_DONE:
            valid_transition = (new_state == TLSState::ERROR);
            break;
            
        case TLSState::ERROR:
            valid_transition = false;  // No transitions out of ERROR state
            break;
    }
    
    if (valid_transition) {
        std::stringstream ss;
        ss << "State transition: " << static_cast<int>(state_) << " -> " << static_cast<int>(new_state);
        tls_log_.log(std::make_shared<ConnLogEntry>(key_, ss.str()));
        std::cout << ss.str() << std::endl;
        
        state_ = new_state;
    }
}

void TLSAnalyzer::reset() {
    state_ = TLSState::INIT;
    client_buffer_.reset();
    server_buffer_.reset();
}
