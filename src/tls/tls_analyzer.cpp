#include "tls/tls_analyzer.hpp"
#include "log/conn_log_entry.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

TLSAnalyzer::TLSAnalyzer(const ConnectionKey& key)
    : key_(key),
    client_buffer_([this](const std::string& msg) {
        tls_log_.log(std::make_shared<ConnLogEntry>(key_, msg));
    }),
    server_buffer_([this](const std::string& msg) {
        tls_log_.log(std::make_shared<ConnLogEntry>(key_, msg));
    }),
    state_machine_([this](const std::string& msg) {
        tls_log_.log(std::make_shared<ConnLogEntry>(key_, msg));
    }) {
}

TLSAnalyzer::~TLSAnalyzer() {
    tls_log_.flush();
}

void TLSAnalyzer::on_data(Direction dir, const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << "[TLSAnalyzer] on_data: " << (dir == Direction::CLIENT_TO_SERVER ? "Client->Server" : "Server->Client")
        << " (" << len << " bytes)";
    tls_log_.log(std::make_shared<ConnLogEntry>(key_, oss.str()));

    // Add data to appropriate buffer
    auto& buffer = (dir == Direction::CLIENT_TO_SERVER) ? 
                   client_buffer_ : server_buffer_;
    
    buffer.add_data(data, len);
    
    // Process complete records
    TLSContentType type;
    std::vector<uint8_t> fragment;
    while (buffer.try_extract_record(type, fragment)) {
        handle_record(dir, type, fragment);
    }
}

void TLSAnalyzer::handle_record(Direction dir, TLSContentType type,
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

void TLSAnalyzer::handle_handshake(Direction dir, const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return;
    }

    TLSHandshakeType msg_type = static_cast<TLSHandshakeType>(data[0]);
    state_machine_.process_handshake(dir, msg_type);
}

void TLSAnalyzer::handle_alert(Direction dir, const std::vector<uint8_t>& data) {
    if (data.size() < 2) {
        return;  // Alert message must be at least 2 bytes
    }
    
    tls_log_.log(std::make_shared<ConnLogEntry>(key_, "[Temp] TLS ERROR State"));
    // For now, any alert moves us to ERROR state; 
    // decrpty and seve alert info; todo, also cipher spec info.
    // state_machine_.process_alert(dir); 
}

void TLSAnalyzer::handle_change_cipher_spec(Direction dir) {
    state_machine_.process_change_cipher_spec(dir);
}

void TLSAnalyzer::reset() {
    state_machine_.reset();
    client_buffer_.reset();
    server_buffer_.reset();
}
