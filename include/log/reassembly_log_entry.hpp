#ifndef REASSEMBLY_LOG_ENTRY_HPP
#define REASSEMBLY_LOG_ENTRY_HPP

#include "log_entry.hpp"
#include "definitions/direction.hpp"
#include "definitions/reassm_event.hpp"
#include <string>
#include <sstream>
#include <iomanip>

class ReassemblyLogEntry : public LogEntry {
public:
    ReassemblyLogEntry(
        const ConnectionKey& key,
        Direction direction,
        ReassmEvent event_type,
        uint32_t segment_seq,       // Relevant segment's start SEQ
        size_t segment_len,         // Relevant segment's length (original or processed)
        uint32_t expected_seq       // The value of next_seq_ *before* this event
    );

    std::string format() const override;

private:
    Direction direction_;
    ReassmEvent event_type_;
    uint32_t segment_seq_;
    size_t segment_len_;
    uint32_t expected_seq_;

    std::string event_type_to_string(ReassmEvent type) const;
};

#endif // REASSEMBLY_LOG_ENTRY_HPP
