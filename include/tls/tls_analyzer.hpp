#ifndef TLS_ANALYZER_HPP
#define TLS_ANALYZER_HPP

#include "definitions/direction.hpp"
#include "definitions/tls_types.hpp"
#include "conn/connection_key.hpp"
#include "interfaces/protocol_analyzer.hpp"
#include "tls/tls_recorder.hpp"
#include "tls/tls12_state_machine.hpp"
#include "log/log_manager.hpp"
#include <memory>

class TLSAnalyzer : public IProtocolAnalyzer {
public:
    // Create analyzer for a specific TCP connection
    explicit TLSAnalyzer(const ConnectionKey& key);
    ~TLSAnalyzer();

    // IProtocolAnalyzer interface implementation
    void on_data(Direction dir, 
                 const uint8_t* data, 
                 size_t len) override;

    // TLS-specific interface
    TLS12State get_state() const { return state_machine_.get_state(); }
    bool is_handshake_complete() const { return state_machine_.get_state() == TLS12State::HANDSHAKE_COMPLETE; }
    
    // Reset analyzer state
    void reset();

private:
    // Process a complete TLS record
    void handle_record(Direction dir, TLSContentType type, 
                      const std::vector<uint8_t>& fragment);
    
    // Handle specific message types
    void handle_handshake(Direction dir, const std::vector<uint8_t>& data);
    void handle_alert(Direction dir, const std::vector<uint8_t>& data);
    void handle_change_cipher_spec(Direction dir);
    
    ConnectionKey key_;
    TLS12StateMachine state_machine_;
    TLSRecorder client_buffer_;
    TLSRecorder server_buffer_;
    Log& tls_log_ = LogManager::get_instance().get_registered_log("tls.log");
};

#endif // TLS_ANALYZER_HPP
