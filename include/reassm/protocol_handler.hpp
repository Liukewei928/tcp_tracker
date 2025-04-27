#ifndef PROTOCOL_HANDLER_HPP
#define PROTOCOL_HANDLER_HPP

#include "interfaces/protocol_analyzer.hpp"
#include <memory>
#include <vector>
#include <algorithm>

class ProtocolHandler {
public:
    // Add a protocol analyzer
    void add_analyzer(std::shared_ptr<IProtocolAnalyzer> analyzer);

    // Remove a protocol analyzer
    void remove_analyzer(const std::shared_ptr<IProtocolAnalyzer>& analyzer);
       
    // Notify all analyzers of new data
    void notify_data(ReassemblyDirection dir, const uint8_t* data, size_t len);

    // Notify connection events
    void notify_reset();
    void notify_closed();

private:
    std::vector<std::shared_ptr<IProtocolAnalyzer>> analyzers_;
};

#endif // PROTOCOL_HANDLER_HPP
