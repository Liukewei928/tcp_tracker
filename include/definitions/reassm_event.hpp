#ifndef REASSM_EVENT_HPP
#define REASSM_EVENT_HPP

// Define specific events related to reassembly
enum class ReassmEvent {
    SEGMENT_RECEIVED,        // Packet payload arrived for potential reassembly
    SEGMENT_BUFFERED,        // Segment placed in out-of-order buffer
    SEGMENT_DELIVERED_IN_ORDER,// Segment delivered directly (matched next_seq)
    SEGMENT_DELIVERED_BUFFERED,// Segment delivered from the out-of-order buffer
    SEGMENT_DUPLICATE_DISCARDED,     // Segment discarded as a duplicate
    SEGMENT_OLD_DISCARDED,   // Segment discarded because it's entirely before next_seq
    SEGMENT_OVERLAP_TRIMMED,         // Start of segment trimmed due to overlap with delivered data
    BUFFER_RESET,            // Reassembly buffer cleared (e.g., on RST)
    FIN_SIGNALED,            // FIN flag processed for this direction
    SEQ_INITIALIZED,         // Initial sequence number set
    DATA_IGNORED_FIN,        // Data ignored due to FIN already received
    DATA_IGNORED_INIT,       // Data ignored due to initial sequence number not set
    SEGMENT_INVALID,         // Segment is invalid (e.g., zero length)
    SEGMENT_OUT_OF_ORDER    // Segment is out of order and needs to be buffered
};

#endif // REASSM_EVENT_HPP
