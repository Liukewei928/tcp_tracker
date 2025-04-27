#ifndef ANALYZER_REGISTRY_HPP
#define ANALYZER_REGISTRY_HPP

#include "interfaces/protocol_analyzer.hpp"
#include "conn/connection_key.hpp"
#include <unordered_map>
#include <functional>
#include <memory>
#include <vector>
#include <string>

class AnalyzerRegistry {
public:
    using AnalyzerCreator = std::function<std::shared_ptr<IProtocolAnalyzer>(const ConnectionKey&)>;
    using AnalyzerConfig = std::unordered_map<std::string, std::string>;

    static AnalyzerRegistry& get_instance();

    // Register a new analyzer type
    void register_analyzer(const std::string& name, 
                         AnalyzerCreator creator, 
                         const std::string& description = "");

    // Create analyzers based on names
    std::vector<std::shared_ptr<IProtocolAnalyzer>> create_analyzers(
        const ConnectionKey& key,
        const std::vector<std::string>& analyzer_names) const;

    // Create a single analyzer
    std::shared_ptr<IProtocolAnalyzer> create_analyzer(
        const std::string& name,
        const ConnectionKey& key) const;

    // Get list of registered analyzers
    std::vector<std::string> get_registered_analyzers() const;

    // Get analyzer description
    std::string get_analyzer_description(const std::string& name) const;

    // Check if analyzer is registered
    bool is_analyzer_registered(const std::string& name) const;

private:
    AnalyzerRegistry() = default;
    ~AnalyzerRegistry() = default;
    
    AnalyzerRegistry(const AnalyzerRegistry&) = delete;
    AnalyzerRegistry& operator=(const AnalyzerRegistry&) = delete;

    struct AnalyzerInfo {
        AnalyzerCreator creator;
        std::string description;
    };

    std::unordered_map<std::string, AnalyzerInfo> analyzers_;
};

#endif // ANALYZER_REGISTRY_HPP
