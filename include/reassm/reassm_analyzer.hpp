#ifndef REASSM_ANALYZER_HPP
#define REASSM_ANALYZER_HPP

#include "interfaces/protocol_analyzer.hpp"
#include "conn/connection_key.hpp"
#include "log/log.hpp"
#include <memory>

class ReassmAnalyzer : public IProtocolAnalyzer {
public:
    explicit ReassmAnalyzer(const ConnectionKey& key, bool debug_mode = false);
    ~ReassmAnalyzer() override;

    // IProtocolAnalyzer interface implementation
    void on_data(ReassemblyDirection dir, 
                 const uint8_t* data, 
                 size_t len) override;
    
    void on_connection_reset() override;
    void on_connection_closed() override;

private:
    ConnectionKey key_;
    bool debug_mode_;
    Log reassm_analyzer_log_;  // Separate log for reassembly debug info

    void log_data(ReassemblyDirection dir, 
                  const uint8_t* data, 
                  size_t len);
    void log_event(const std::string& event);
};

#endif // REASSM_ANALYZER_HPP
