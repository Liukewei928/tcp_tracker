#ifndef PROTOCOL_ANALYZER_HPP
#define PROTOCOL_ANALYZER_HPP

#include "definations/reassembly_def.hpp"
#include <cstdint>
#include <cstddef>

class IProtocolAnalyzer {
public:
    virtual ~IProtocolAnalyzer() = default;
    
    // Process reassembled data
    virtual void on_data(ReassemblyDirection dir, 
                        const uint8_t* data, 
                        size_t len) = 0;

    // Optional: Handle connection events
    virtual void on_connection_reset() {}
    virtual void on_connection_closed() {}
};

#endif // PROTOCOL_ANALYZER_HPP
