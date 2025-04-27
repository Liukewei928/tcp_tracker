#ifndef TCP_REASSEMBLY_DEF_HPP
#define TCP_REASSEMBLY_DEF_HPP

enum class ReassemblyDirection {
    CLIENT_TO_SERVER, // Data flow C->S, buffer held by server logic
    SERVER_TO_CLIENT  // Data flow S->C, buffer held by client logic
};

// Define specific events related to reassembly
enum class ReassemblyEventType {
    SegmentReceived,        // Packet payload arrived for potential reassembly
    SegmentBuffered,        // Segment placed in out-of-order buffer
    SegmentDeliveredInOrder,// Segment delivered directly (matched next_seq)
    SegmentDeliveredBuffered,// Segment delivered from the out-of-order buffer
    DuplicateDiscarded,     // Segment discarded as a duplicate
    OldSegmentDiscarded,    // Segment discarded because it's entirely before next_seq
    OverlapTrimmed,         // Start of segment trimmed due to overlap with delivered data
    BufferReset,            // Reassembly buffer cleared (e.g., on RST)
    FinSignaled,            // FIN flag processed for this direction
    SeqInitialized,         // Initial sequence number set
    DataIgnoredFin,         // Data ignored due to FIN already received
    DataIgnoredInit         // Data ignored due to initial sequence number not set
};

#endif // TCP_REASSEMBLY_DEF_HPP
