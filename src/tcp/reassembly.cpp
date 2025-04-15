#include "tcp/reassembly.hpp"
#include "tcp/connection_key.hpp"
#include "log/reassembly_log_entry.hpp"
#include <algorithm> // For std::min
#include <vector>
#include <iostream> // For potential stderr debug

Reassebly::Reassebly(const ConnectionKey& key, ReassemblyDirection dir, bool debug_mode, DataCallback cb)
    : key_(key),
      direction_(dir),
      reassembly_log_("reassembly.log", debug_mode),
      data_callback_(std::move(cb)),
      next_seq_(0),
      initial_seq_set_(false),
      fin_received_(false)
{}

Reassebly::~Reassebly() {
    reassembly_log_.flush(); // Ensure logs are written on destruction
}

void Reassebly::log_event(ReassemblyEventType type, uint32_t seq, size_t len) {
    reassembly_log_.log(std::make_shared<ReassemblyLogEntry>(
        key_, direction_, type, seq, len, next_seq_));
}

void Reassebly::set_initial_seq(uint32_t isn) {
    if (!initial_seq_set_) {
        next_seq_ = isn;
        initial_seq_set_ = true;
        log_event(ReassemblyEventType::SeqInitialized, 0, 0); // Log INIT, use expected_seq field for isn
        // Immediately try to deliver any buffered data starting at this ISN
        deliver_contiguous();
    }
}

void Reassebly::reset() {
    if (initial_seq_set_ || !out_of_order_segments_.empty()) { // Only log reset if there was state
        log_event(ReassemblyEventType::BufferReset);
    }
    out_of_order_segments_.clear();
    next_seq_ = 0;
    initial_seq_set_ = false;
    fin_received_ = false;
}

void Reassebly::fin_received() {
    if (!fin_received_) { // Log only on first signal
         fin_received_ = true;
         log_event(ReassemblyEventType::FinSignaled);
         // Check if FIN allows delivery of final buffered segment
         deliver_contiguous();
    }
}

void Reassebly::process(uint32_t seq, const uint8_t* payload, size_t payload_len, bool syn_flag, bool fin_flag) {

    log_event(ReassemblyEventType::SegmentReceived, seq, payload_len);

    if (!initial_seq_set_) {
        log_event(ReassemblyEventType::DataIgnoredInit, seq, payload_len);
        return; // Cannot process data if sequence isn't initialized
    }
    // Allow processing even if FIN received, but log ignore later if needed
    // if (fin_received_) { ... }

    // Calculate the sequence number of the last byte + 1
    uint32_t end_seq = seq + static_cast<uint32_t>(payload_len);

    // --- Basic Sanity Checks & Duplicate/Old Data Handling ---
    if (payload_len > 0 && !seq_gt(end_seq, next_seq_)) {
        // Segment entirely before expected sequence (Old data or duplicate)
        log_event(ReassemblyEventType::OldSegmentDiscarded, seq, payload_len);
        return;
    }

    // --- Trim Overlapping Data at the Beginning ---
    uint32_t original_seq = seq; // Keep original for potential logging
    size_t original_len = payload_len;
    const uint8_t* current_payload = payload;
    size_t current_payload_len = payload_len;

    bool trimmed = false;
    if (payload_len > 0 && seq_gt(next_seq_, seq)) {
        uint32_t overlap = next_seq_ - seq;
        if (overlap >= current_payload_len) {
            // Entire segment is already delivered overlap
            log_event(ReassemblyEventType::DuplicateDiscarded, seq, payload_len); // Treat as duplicate
            return;
        }
        seq = next_seq_; // Advance segment seq to expected start
        current_payload += overlap;
        current_payload_len -= overlap;
        trimmed = true;
        log_event(ReassemblyEventType::OverlapTrimmed, original_seq, original_len);
    }

    // Check fin_received *after* trimming/checking for overlap
     if (fin_received_ && current_payload_len > 0) {
         log_event(ReassemblyEventType::DataIgnoredFin, seq, current_payload_len);
         // Still process FIN flag below if present, but ignore payload
         current_payload_len = 0;
     }


    // --- Process the (potentially trimmed) segment ---
    if (current_payload_len > 0 && seq == next_seq_) {
        // Segment starts exactly where expected - Deliver it
        log_event(ReassemblyEventType::SegmentDeliveredInOrder, seq, current_payload_len);
        if (data_callback_) {
            data_callback_(direction_, current_payload, current_payload_len);
        }
        next_seq_ += static_cast<uint32_t>(current_payload_len);

        // Try to deliver buffered segments now that next_seq_ has advanced
        deliver_contiguous();

    } else if (payload_len > 0 && seq_gt(seq, next_seq_)) { // Use original payload_len check for buffer decision
        // Segment is in the future - Buffer it
        // Use the potentially trimmed values (seq, current_payload, current_payload_len) for buffer
         log_event(ReassemblyEventType::SegmentBuffered, seq, current_payload_len);
         // Simple buffering: Overwrite if segment with same start SEQ exists.
         // TODO: Add logic here to avoid buffering segments that overlap existing buffer entries partially.
         // For now, simple insert/assign:
        out_of_order_segments_.insert_or_assign(seq,
            std::vector<uint8_t>(current_payload, current_payload + current_payload_len));
    }
    // Else: Segment has zero payload length (pure ACK or FIN handled below)

    // --- Handle FIN Flag ---
    // FIN consumes a sequence number *after* the payload
    if (fin_flag) {
        uint32_t fin_seq = original_seq + static_cast<uint32_t>(original_len); // FIN seq based on original segment end
        // Only process FIN if it's the *next* expected sequence number *after* current data delivery
        if (fin_seq == next_seq_ && !fin_received_) {
             fin_received(); // Calls internal method which logs and sets flag
             next_seq_++; // Consume FIN's sequence number
        }
        // Note: We don't buffer future FINs explicitly here; rely on state machine calling fin_received()
    }
}

void Reassebly::deliver_contiguous() {
    // Can only deliver if initialized
    if (!initial_seq_set_) return;

    // Keep delivering as long as the next expected segment is in the buffer
    auto it = out_of_order_segments_.begin();
    while (it != out_of_order_segments_.end() && it->first == next_seq_) {
        const std::vector<uint8_t>& segment_data = it->second;

        // Check if delivering this buffered data goes past an already processed FIN
        // This check might be slightly complex depending on exact FIN handling.
        // Basic check: if FIN is received, don't deliver data strictly *after* it?
        // If FIN consumes seq N+1, data up to N is okay.
        // If fin_received_ is true, next_seq_ might already be FIN_Seq+1.
        // Let's assume for now deliver_contiguous won't run if fin_received_ blocks things.

        log_event(ReassemblyEventType::SegmentDeliveredBuffered, it->first, segment_data.size());

        if (data_callback_) {
            data_callback_(direction_, segment_data.data(), segment_data.size());
        }
        next_seq_ += static_cast<uint32_t>(segment_data.size());

        // Remove the delivered segment and advance iterator safely
        it = out_of_order_segments_.erase(it);
    }
}
