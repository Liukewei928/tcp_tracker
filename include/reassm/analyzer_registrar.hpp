#ifndef ANALYZER_REGISTRAR_HPP
#define ANALYZER_REGISTRAR_HPP

#include "reassm/analyzer_registry.hpp"

class AnalyzerRegistrar {
public:
    static std::vector<std::string> create_analyzers(const std::vector<std::string>& enabled_analyzers);
    static void register_default_analyzers();
    static void register_tls_analyzer();
    static void register_reassm_analyzer();
    static void register_custom_analyzer(
        const std::string& name,
        AnalyzerRegistry::AnalyzerCreator creator,
        const std::string& description = "");
};

#endif // ANALYZER_REGISTRAR_HPP
