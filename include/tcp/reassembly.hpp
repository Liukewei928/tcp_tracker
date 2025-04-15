#ifndef TCP_REASSEMBLY_HPP
#define TCP_REASSEMBLY_HPP

#include "tcp_def/tcp_state.hpp"
#include "tcp_def/reassembly_def.hpp"
#include "tcp/connection_key.hpp"
#include "log/log.hpp"
#include <cstdint>
#include <vector>
#include <map>
#include <functional>
#include <optional>

// Helper sequence comparison functions (inline)
inline bool seq_gt(uint32_t seq1, uint32_t seq2) {
    return static_cast<int32_t>(seq1 - seq2) > 0;
}
inline bool seq_ge(uint32_t seq1, uint32_t seq2) {
    return static_cast<int32_t>(seq1 - seq2) >= 0;
}

class Reassebly {
public:
    // Callback type remains the same: void(direction, data_ptr, data_len)
    using DataCallback = std::function<void(ReassemblyDirection, const uint8_t*, size_t)>;

    Reassebly(const ConnectionKey& key, ReassemblyDirection dir, bool debug_mode, DataCallback cb);

    ~Reassebly();

    // Process an incoming TCP segment's payload for this direction
    void process(uint32_t seq, const uint8_t* payload, size_t payload_len, bool syn_flag, bool fin_flag);

    // Set the initial expected sequence number (usually after handshake)
    void set_initial_seq(uint32_t isn);

    // Reset buffer state (e.g., on RST)
    void reset();

    // Signal that a FIN has been received for this direction
    void fin_received();

    // --- Accessors ---
    uint32_t get_next_seq() const { return next_seq_; }
    bool is_initialized() const { return initial_seq_set_; }
    bool is_closed() const { return fin_received_; }

private:
    ConnectionKey key_; // Store key for logging context
    ReassemblyDirection direction_;
    Log reassembly_log_;

    DataCallback data_callback_;
    uint32_t next_seq_ = 0;
    bool initial_seq_set_ = false;
    bool fin_received_ = false;

    // Buffer for out-of-order segments: map<start_seq, payload_vector>
    std::map<uint32_t, std::vector<uint8_t>> out_of_order_segments_;

    // Internal helper to deliver contiguous data
    void deliver_contiguous();

    // Internal log helper (optional)
    void log_event(ReassemblyEventType type, uint32_t seq = 0, size_t len = 0);
};

#endif // TCP_REASSEMBLY_HPP