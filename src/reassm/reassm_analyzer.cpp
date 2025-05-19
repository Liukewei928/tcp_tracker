#include "reassm/reassm_analyzer.hpp"
#include "log/conn_log_entry.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

ReassmAnalyzer::ReassmAnalyzer(const ConnectionKey& key)
    : key_(key) {
}

ReassmAnalyzer::~ReassmAnalyzer() {
    reassm_analyzer_log_.flush();
}

void ReassmAnalyzer::on_data(Direction dir, const uint8_t* data, size_t len) {
    std::stringstream ss;
    
    // Log basic info
    ss << "Reassembled Data - "
       << (dir == Direction::CLIENT_TO_SERVER ? "Client->Server" : "Server->Client")
       << " (" << len << " bytes)\n";

    // Hex dump
    ss << "Hex dump:\n";
    for (size_t i = 0; i < len; ++i) {
        if (i % 16 == 0) {
            if (i > 0) ss << std::endl;
            ss << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
        }
        ss << std::setw(2) << std::setfill('0') << std::hex 
           << static_cast<int>(data[i]) << " ";
    }
    ss << std::endl;

    // ASCII representation
    ss << "ASCII:\n";
    for (size_t i = 0; i < len; ++i) {
        char c = data[i];
        ss << (isprint(c) ? c : '.');
    }
    ss << std::endl;

    // Log the formatted output
    reassm_analyzer_log_.log(std::make_shared<ConnLogEntry>(key_, ss.str()));
}

void ReassmAnalyzer::on_connection_reset() {
    reassm_analyzer_log_.log(std::make_shared<ConnLogEntry>(key_, "Connection Reset"));
}

void ReassmAnalyzer::on_connection_closed() {
    reassm_analyzer_log_.log(std::make_shared<ConnLogEntry>(key_, "Connection Closed"));
}
