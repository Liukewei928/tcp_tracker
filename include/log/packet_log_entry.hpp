#ifndef PACKET_LOG_ENTRY_HPP
#define PACKET_LOG_ENTRY_HPP

#include "log/log_entry.hpp"
#include "definitions/packet_key.hpp"
#include "conn/connection_key.hpp"

class PacketLogEntry : public LogEntry {
public:
    PacketLogEntry(const ConnectionKey& key, const PacketKey& pkey);
    std::string format() const override;

private:
    const PacketKey pkey_;
};

#endif // PACKET_LOG_ENTRY_HPP
