#include "reassm/reassm_analyzer.hpp"
#include "log/conn_log_entry.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

ReassmAnalyzer::ReassmAnalyzer(const ConnectionKey& key, bool debug_mode)
    : key_(key)
    , debug_mode_(debug_mode)
    , reassm_analyzer_log_("reassm_analyzer.log", debug_mode) {
}

ReassmAnalyzer::~ReassmAnalyzer() {
    reassm_analyzer_log_.flush();
}

void ReassmAnalyzer::on_data(ReassemblyDirection dir, 
                            const uint8_t* data, 
                            size_t len) {
    if (!debug_mode_) return;

    log_data(dir, data, len);
}

void ReassmAnalyzer::on_connection_reset() {
    if (!debug_mode_) return;
    log_event("Connection Reset");
}

void ReassmAnalyzer::on_connection_closed() {
    if (!debug_mode_) return;
    log_event("Connection Closed");
}

void ReassmAnalyzer::log_data(ReassemblyDirection dir, 
                             const uint8_t* data, 
                             size_t len) {
    std::stringstream ss;
    
    // Log basic info
    ss << "Reassembled Data - "
       << (dir == ReassemblyDirection::CLIENT_TO_SERVER ? "Client->Server" : "Server->Client")
       << " (" << len << " bytes)\n";

    // Hex dump
    ss << "Hex dump:\n";
    for (size_t i = 0; i < len; ++i) {
        if (i % 16 == 0) {
            if (i > 0) ss << "\n";
            ss << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
        }
        ss << std::setw(2) << std::setfill('0') << std::hex 
           << static_cast<int>(data[i]) << " ";
    }
    ss << "\n";

    // ASCII representation
    ss << "ASCII:\n";
    for (size_t i = 0; i < len; ++i) {
        char c = data[i];
        ss << (isprint(c) ? c : '.');
    }
    ss << "\n";

    // Log the formatted output
    reassm_analyzer_log_.log(std::make_shared<ConnLogEntry>(key_, ss.str()));

    // Also print to stdout for immediate feedback
    std::cout << ss.str() << std::endl;
}

void ReassmAnalyzer::log_event(const std::string& event) {
    std::stringstream ss;
    ss << "Event: " << event;
    reassm_analyzer_log_.log(std::make_shared<ConnLogEntry>(key_, ss.str()));
    std::cout << ss.str() << std::endl;
}
