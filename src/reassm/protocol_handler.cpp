#include "reassm/protocol_handler.hpp"

void ProtocolHandler::add_analyzer(std::shared_ptr<IProtocolAnalyzer> analyzer) {
    analyzers_.push_back(std::move(analyzer));
}

void ProtocolHandler::remove_analyzer(const std::shared_ptr<IProtocolAnalyzer>& analyzer) {
    analyzers_.erase(
        std::remove(analyzers_.begin(), analyzers_.end(), analyzer),
        analyzers_.end()
    );
}

void ProtocolHandler::notify_data(ReassemblyDirection dir, const uint8_t* data, size_t len) {
    for (const auto& analyzer : analyzers_) {
        analyzer->on_data(dir, data, len);
    }
}

void ProtocolHandler::notify_reset() {
    for (const auto& analyzer : analyzers_) {
        analyzer->on_connection_reset();
    }
}

void ProtocolHandler::notify_closed() {
    for (const auto& analyzer : analyzers_) {
        analyzer->on_connection_closed();
    }
}
