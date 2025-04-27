#include "reassm/analyzer_registrar.hpp"
#include "tls/tls_analyzer.hpp"
#include "reassm/reassm_analyzer.hpp"
#include <iostream>

void AnalyzerRegistrar::register_default_analyzers() {
    register_tls_analyzer();
    register_reassm_analyzer();
}

void AnalyzerRegistrar::register_tls_analyzer() {
    auto creator = [](const ConnectionKey& key) {
        return std::make_shared<TLSAnalyzer>(key);
    };
    
    AnalyzerRegistry::get_instance().register_analyzer(
        "tls",
        creator,
        "TLS protocol analyzer for tracking handshake and state"
    );
}

void AnalyzerRegistrar::register_reassm_analyzer() {
    auto reassm_creator = [](const ConnectionKey& key) {
        return std::make_shared<ReassmAnalyzer>(key, true);
    };

    AnalyzerRegistry::get_instance().register_analyzer(
        "reassm",
        reassm_creator,
        "Reassembly debug analyzer for tracking TCP stream reassembly"
    );
}

void AnalyzerRegistrar::register_custom_analyzer(
    const std::string& name,
    AnalyzerRegistry::AnalyzerCreator creator,
    const std::string& description) {
    
    AnalyzerRegistry::get_instance().register_analyzer(
        name,
        std::move(creator),
        description
    );
}