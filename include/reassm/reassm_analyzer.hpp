#ifndef REASSM_ANALYZER_HPP
#define REASSM_ANALYZER_HPP

#include "interfaces/protocol_analyzer.hpp"
#include "conn/connection_key.hpp"
#include "log/log_manager.hpp"
#include <memory>

class ReassmAnalyzer : public IProtocolAnalyzer {
public:
    explicit ReassmAnalyzer(const ConnectionKey& key);
    ~ReassmAnalyzer() override;

    void on_data(Direction dir, const uint8_t* data, size_t len) override;
    void on_connection_reset() override;
    void on_connection_closed() override;

private:
    ConnectionKey key_;
    Log& reassm_analyzer_log_ = LogManager::get_instance().get_registered_log("reassm_data.log");
};

#endif // REASSM_ANALYZER_HPP
