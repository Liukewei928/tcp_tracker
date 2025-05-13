#ifndef TLS_ANALYZER_HPP
#define TLS_ANALYZER_HPP

#include "definations/reassembly_def.hpp"
#include "definations/tls_types.hpp"
#include "conn/connection_key.hpp"
#include "interfaces/protocol_analyzer.hpp"
#include "tls/tls_record.hpp"
#include "log/log_manager.hpp"
#include <memory>

class TLSAnalyzer : public IProtocolAnalyzer {
public:
    // Create analyzer for a specific TCP connection
    explicit TLSAnalyzer(const ConnectionKey& key);
    ~TLSAnalyzer();

    // IProtocolAnalyzer interface implementation
    void on_data(ReassemblyDirection dir, 
                 const uint8_t* data, 
                 size_t len) override;

    // TLS-specific interface
    TLSState get_state() const { return state_; }
    bool is_handshake_complete() const { return state_ == TLSState::HANDSHAKE_DONE; }
    
    // Reset analyzer state
    void reset();

private:

    // Process a complete TLS record
    void handle_record(ReassemblyDirection dir, TLSContentType type, 
                      const std::vector<uint8_t>& fragment);
    
    // Handle specific message types
    void handle_handshake(ReassemblyDirection dir, const std::vector<uint8_t>& data);
    void handle_alert(ReassemblyDirection dir, const std::vector<uint8_t>& data);
    void handle_change_cipher_spec(ReassemblyDirection dir);
    
    // Update state machine
    void update_state(TLSState new_state);

    ConnectionKey key_;
    TLSState state_ = TLSState::INIT;
    TLSBuffer client_buffer_;
    TLSBuffer server_buffer_;
    Log& tls_log_ = LogManager::get_instance().get_registered_log("tls.log");;
};

#endif // TLS_ANALYZER_HPP
