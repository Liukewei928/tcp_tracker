#include "log/reassembly_log_entry.hpp"

ReassemblyLogEntry::ReassemblyLogEntry(
    const ConnectionKey& key,
    Direction direction,
    ReassmEvent event_type,
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
        case ReassmEvent::SEGMENT_RECEIVED:
        case ReassmEvent::SEGMENT_BUFFERED:
        case ReassmEvent::SEGMENT_DELIVERED_IN_ORDER:
        case ReassmEvent::SEGMENT_DELIVERED_BUFFERED:
        case ReassmEvent::SEGMENT_DUPLICATE_DISCARDED:
        case ReassmEvent::SEGMENT_OLD_DISCARDED:
        case ReassmEvent::SEGMENT_OVERLAP_TRIMMED:
        case ReassmEvent::SEGMENT_INVALID:
        case ReassmEvent::SEGMENT_OUT_OF_ORDER:
            oss << " | Seq:" << segment_seq_
                << " Len:" << segment_len_
                << " Expect:" << expected_seq_;
            break;
        case ReassmEvent::SEQ_INITIALIZED:
            oss << " | InitialSeq:" << expected_seq_; // expected_seq holds the init value here
            break;
        case ReassmEvent::BUFFER_RESET:
            oss << " | LastExpected:" << expected_seq_; // Show what was expected before reset
            break;
        case ReassmEvent::FIN_SIGNALED:
            oss << " | Expecting:" << expected_seq_; // Show what was expected when FIN arrived
            break;
        case ReassmEvent::DATA_IGNORED_FIN:
        case ReassmEvent::DATA_IGNORED_INIT:
            oss << " | Seq:" << segment_seq_ << " Len:" << segment_len_;
            break;
        default:
            break;
    }

    return oss.str();
}

std::string ReassemblyLogEntry::event_type_to_string(ReassmEvent type) const {
    switch (type) {
        case ReassmEvent::SEGMENT_RECEIVED: return "RECV";
        case ReassmEvent::SEGMENT_BUFFERED: return "BUFF";
        case ReassmEvent::SEGMENT_DELIVERED_IN_ORDER: return "DLVR_ORD";
        case ReassmEvent::SEGMENT_DELIVERED_BUFFERED: return "DLVR_BUF";
        case ReassmEvent::SEGMENT_DUPLICATE_DISCARDED: return "DROP_DUP";
        case ReassmEvent::SEGMENT_OLD_DISCARDED: return "DROP_OLD";
        case ReassmEvent::SEGMENT_OVERLAP_TRIMMED: return "TRIM";
        case ReassmEvent::BUFFER_RESET: return "RESET";
        case ReassmEvent::FIN_SIGNALED: return "FIN";
        case ReassmEvent::SEQ_INITIALIZED: return "INIT";
        case ReassmEvent::DATA_IGNORED_FIN: return "IGN_FIN";
        case ReassmEvent::DATA_IGNORED_INIT: return "IGN_INIT";
        case ReassmEvent::SEGMENT_INVALID: return "INVALID";
        case ReassmEvent::SEGMENT_OUT_OF_ORDER: return "OUT_OF_ORDER";
        default: return "UNK";
    }
}
