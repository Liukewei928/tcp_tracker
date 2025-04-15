#ifndef REASSEMBLY_LOG_ENTRY_HPP
#define REASSEMBLY_LOG_ENTRY_HPP

#include "log_entry.hpp"
#include "tcp/connection_key.hpp"
#include "tcp/tcp_reassembly.hpp"
#include <string>
#include <sstream>
#include <iomanip>

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
    FinSignaled             // FIN flag processed for this direction
};

class ReassemblyLogEntry : public LogEntry {
public:
    ReassemblyLogEntry(
        const ConnectionKey& key,
        ReassemblyDirection direction,
        ReassemblyEventType event_type,
        uint32_t segment_seq,
        size_t segment_len,
        uint32_t expected_seq, // The value of next_seq_ *before* this event
    ) : 
        key_(key),
        direction_(direction),
        event_type_(event_type),
        segment_seq_(segment_seq),
        segment_len_(segment_len),
        expected_seq_(expected_seq)
        {}

    std::string to_string() const override {
        std::ostringstream oss;
        oss << get_timestamp()
			<< key_.src_ip << ":" << key_.src_port << " -> " << key_.dst_ip << ":" << key_.dst_port << " "
            << (direction_ == ReassemblyDirection::CLIENT_TO_SERVER ? "C->S" : "S->C") << " | "
            << "Event: " << event_type_to_string(event_type_)
            << ", Seq: " << segment_seq_
            << ", Len: " << segment_len_
            << ", Expecting: " << expected_seq_;

        return oss.str();
    }

private:
    ConnectionKey key_;
    ReassemblyDirection direction_;
    ReassemblyEventType event_type_;
    uint32_t segment_seq_;
    size_t segment_len_;
    uint32_t expected_seq_;

    std::string event_type_to_string(ReassemblyEventType type) const {
        switch (type) {
            case ReassemblyEventType::SegmentReceived: return "SEG_RECV";
            case ReassemblyEventType::SegmentBuffered: return "SEG_BUFF";
            case ReassemblyEventType::SegmentDeliveredInOrder: return "DLVR_INORDER";
            case ReassemblyEventType::SegmentDeliveredBuffered: return "DLVR_BUFFER";
            case ReassemblyEventType::DuplicateDiscarded: return "DROP_DUP";
            case ReassemblyEventType::OldSegmentDiscarded: return "DROP_OLD";
            case ReassemblyEventType::OverlapTrimmed: return "TRIM_OVERLAP";
            case ReassemblyEventType::BufferReset: return "BUFF_RESET";
            case ReassemblyEventType::FinSignaled: return "FIN_SIGNALED";
            default: return "UNKNOWN";
        }
    }
};

#endif // REASSEMBLY_LOG_ENTRY_HPP
