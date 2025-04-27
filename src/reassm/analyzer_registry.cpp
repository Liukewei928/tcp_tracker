#include "reassm/analyzer_registry.hpp"
#include <stdexcept>

AnalyzerRegistry& AnalyzerRegistry::get_instance() {
    static AnalyzerRegistry instance;
    return instance;
}

void AnalyzerRegistry::register_analyzer(
    const std::string& name,
    AnalyzerCreator creator,
    const std::string& description) {
    
    if (creator == nullptr) {
        throw std::invalid_argument("Creator function cannot be null");
    }

    analyzers_[name] = AnalyzerInfo{std::move(creator), description};
}

std::vector<std::shared_ptr<IProtocolAnalyzer>> 
AnalyzerRegistry::create_analyzers(
    const ConnectionKey& key,
    const std::vector<std::string>& analyzer_names) const {
    
    std::vector<std::shared_ptr<IProtocolAnalyzer>> analyzers;
    
    for (const auto& name : analyzer_names) {
        if (auto analyzer = create_analyzer(name, key)) {
            analyzers.push_back(std::move(analyzer));
        }
    }
    
    return analyzers;
}

std::shared_ptr<IProtocolAnalyzer> 
AnalyzerRegistry::create_analyzer(
    const std::string& name,
    const ConnectionKey& key) const {
    
    auto it = analyzers_.find(name);
    if (it == analyzers_.end()) {
        return nullptr;
    }
    
    return it->second.creator(key);
}

std::vector<std::string> 
AnalyzerRegistry::get_registered_analyzers() const {
    std::vector<std::string> names;
    for (const auto& [name, _] : analyzers_) {
        names.push_back(name);
    }
    return names;
}

std::string 
AnalyzerRegistry::get_analyzer_description(const std::string& name) const {
    auto it = analyzers_.find(name);
    return it != analyzers_.end() ? it->second.description : "";
}

bool 
AnalyzerRegistry::is_analyzer_registered(const std::string& name) const {
    return analyzers_.find(name) != analyzers_.end();
}
