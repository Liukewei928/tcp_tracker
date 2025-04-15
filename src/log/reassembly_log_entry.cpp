#include "log/reassembly_log_entry.hpp"

ReassemblyLogEntry::ReassemblyLogEntry(
    const ConnectionKey& key,
    ReassemblyDirection direction,
    ReassemblyEventType event_type,
    uint32_t segment_seq,
    size_t segment_len,
    uint32_t expected_seq
) : LogEntry(key),
    direction_(direction),
    event_type_(event_type),
    segment_seq_(segment_seq),
    segment_len_(segment_len),
    expected_seq_(expected_seq)
{}

std::string ReassemblyLogEntry::format() const {
    std::ostringstream oss;
    oss << get_timestamp() << get_direction() << event_type_to_string(event_type_);

    // Add context based on event type
    switch (event_type_) {
        case ReassemblyEventType::SegmentReceived:
        case ReassemblyEventType::SegmentBuffered:
        case ReassemblyEventType::SegmentDeliveredInOrder:
        case ReassemblyEventType::SegmentDeliveredBuffered:
        case ReassemblyEventType::DuplicateDiscarded:
        case ReassemblyEventType::OldSegmentDiscarded:
        case ReassemblyEventType::OverlapTrimmed:
            oss << " | Seq:" << segment_seq_
                << " Len:" << segment_len_
                << " Expect:" << expected_seq_;
            break;
        case ReassemblyEventType::SeqInitialized:
            oss << " | InitialSeq:" << expected_seq_; // expected_seq holds the init value here
            break;
        case ReassemblyEventType::BufferReset:
            oss << " | LastExpected:" << expected_seq_; // Show what was expected before reset
            break;
        case ReassemblyEventType::FinSignaled:
            oss << " | Expecting:" << expected_seq_; // Show what was expected when FIN arrived
            break;
        case ReassemblyEventType::DataIgnoredFin:
        case ReassemblyEventType::DataIgnoredInit:
            oss << " | Seq:" << segment_seq_ << " Len:" << segment_len_;
            break;
    default:
        break;
    }

    return oss.str();
}

std::string ReassemblyLogEntry::event_type_to_string(ReassemblyEventType type) const {
    switch (type) {
        case ReassemblyEventType::SegmentReceived: return "RECV";
        case ReassemblyEventType::SegmentBuffered: return "BUFF";
        case ReassemblyEventType::SegmentDeliveredInOrder: return "DLVR_ORD";
        case ReassemblyEventType::SegmentDeliveredBuffered: return "DLVR_BUF";
        case ReassemblyEventType::DuplicateDiscarded: return "DROP_DUP";
        case ReassemblyEventType::OldSegmentDiscarded: return "DROP_OLD";
        case ReassemblyEventType::OverlapTrimmed: return "TRIM";
        case ReassemblyEventType::BufferReset: return "RESET";
        case ReassemblyEventType::FinSignaled: return "FIN";
        case ReassemblyEventType::SeqInitialized: return "INIT";
        case ReassemblyEventType::DataIgnoredFin: return "IGN_FIN";
        case ReassemblyEventType::DataIgnoredInit: return "IGN_INIT";
        default: return "UNK";
    }
}
