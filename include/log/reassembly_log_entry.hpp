#ifndef REASSEMBLY_LOG_ENTRY_HPP
#define REASSEMBLY_LOG_ENTRY_HPP

#include "log_entry.hpp"
#include "tcp/connection_key.hpp"
#include "tcp_def/reassembly_def.hpp"
#include <string>
#include <sstream>
#include <iomanip>

class ReassemblyLogEntry : public LogEntry {
public:
    ReassemblyLogEntry(
        const ConnectionKey& key,
        ReassemblyDirection direction,
        ReassemblyEventType event_type,
        uint32_t segment_seq,       // Relevant segment's start SEQ
        size_t segment_len,         // Relevant segment's length (original or processed)
        uint32_t expected_seq       // The value of next_seq_ *before* this event
    );

    std::string format() const override;

private:
    ReassemblyDirection direction_;
    ReassemblyEventType event_type_;
    uint32_t segment_seq_;
    size_t segment_len_;
    uint32_t expected_seq_;

    std::string event_type_to_string(ReassemblyEventType type) const;
};

#endif // REASSEMBLY_LOG_ENTRY_HPP
