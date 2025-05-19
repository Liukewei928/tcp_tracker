#ifndef TCP_REASSEMBLY_HPP
#define TCP_REASSEMBLY_HPP

#include "definitions/reassm_event.hpp"
#include "conn/connection_key.hpp"
#include "log/log_manager.hpp"
#include "interfaces/protocol_analyzer.hpp"
#include "reassm/protocol_handler.hpp"
#include <cstdint>
#include <vector>
#include <map>
#include <functional>
#include <optional>
#include <memory>

// Helper sequence comparison functions (inline)
inline bool seq_gt(uint32_t seq1, uint32_t seq2) {
    return static_cast<int32_t>(seq1 - seq2) > 0;
}
inline bool seq_ge(uint32_t seq1, uint32_t seq2) {
    return static_cast<int32_t>(seq1 - seq2) >= 0;
}

class Reassembly {
public:
    Reassembly(const ConnectionKey& key, Direction dir);
    ~Reassembly();

    // Process an incoming TCP segment's payload for this direction
    void process(uint32_t seq, const uint8_t* payload, size_t payload_len, bool syn_flag, bool fin_flag);

    // Set the initial expected sequence number (usually after handshake)
    void set_initial_seq(uint32_t isn);

    // Reset buffer state (e.g., on RST)
    void reset();

    // Signal that a FIN has been received for this direction
    void fin_received();

    // Add protocol analyzer
    void add_analyzer(std::shared_ptr<IProtocolAnalyzer> analyzer) {
        protocol_handler_.add_analyzer(std::move(analyzer));
    }

    // Remove protocol analyzer
    void remove_analyzer(const std::shared_ptr<IProtocolAnalyzer>& analyzer) {
        protocol_handler_.remove_analyzer(analyzer);
    }

    // --- Accessors ---
    uint32_t get_next_seq() const { return next_seq_; }
    bool is_initialized() const { return initial_seq_set_; }
    bool is_closed() const { return fin_received_; }

private:
    void deliver_contiguous();
    void log_event(ReassmEvent type, uint32_t seq = 0, size_t len = 0);

    ConnectionKey key_;
    Direction direction_;
    ProtocolHandler protocol_handler_;
    Log& reassm_log_ = LogManager::get_instance().get_registered_log("reassm.log");

    uint32_t next_seq_ = 0;
    bool initial_seq_set_ = false;
    bool fin_received_ = false;

    // Buffer for out-of-order segments: map<start_seq, payload_vector>
    std::map<uint32_t, std::vector<uint8_t>> out_of_order_segments_;
};

#endif // TCP_REASSEMBLY_HPP
