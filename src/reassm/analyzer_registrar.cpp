#include "reassm/analyzer_registrar.hpp"
#include "tls/tls_analyzer.hpp"
#include "reassm/reassm_analyzer.hpp"
#include <iostream>

std::vector<std::string> AnalyzerRegistrar::create_analyzers(const std::vector<std::string>& enabled_analyzers) {
    std::vector<std::string> checked_analyzers;
    auto& registry = AnalyzerRegistry::get_instance();

    // Register all available analyzers
    register_default_analyzers();

    // Create dummy key for initial analyzer creation
    ConnectionKey dummy_key;

    // Create enabled analyzers
    for (const auto& analyzer_name : enabled_analyzers) {
        if (registry.is_analyzer_registered(analyzer_name)) {
            if (auto analyzer = registry.create_analyzer(analyzer_name, dummy_key)) {
                checked_analyzers.push_back(analyzer_name);
            } else {
                std::cerr << "Warning: Failed to create analyzer: " 
                    << analyzer_name << std::endl;
            }
        } else {
            std::cerr << "Warning: Unknown analyzer type: " 
                << analyzer_name << std::endl;
        }
    }

    return checked_analyzers;
}

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
        return std::make_shared<ReassmAnalyzer>(key);
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
