#include "conn/packet_processor.hpp"
#include "conn/connection_manager.hpp"  
#include "reassm/analyzer_registry.hpp"
#include "reassm/analyzer_registrar.hpp"
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <thread>
#include <csignal>
#include <atomic>

// Global variables for signal handling
static std::atomic<bool> running(true);
static pcap_t* pcap_handle = nullptr;  // Added to allow signal handler to break pcap_loop

struct ProgramOptions {
    bool debug_mode = false;
    bool truncate_packet_log = false;
    bool truncate_state_log = false;
    int cleanup_interval_seconds = 5;
    std::string filter = "tcp";
    std::vector<std::string> enabled_analyzers;
};

void signal_handler(int signum) {
    std::cout << "Received signal " << signum << std::endl;
    running = false;
    if (pcap_handle) {
        pcap_breakloop(pcap_handle);  // Break the pcap_loop immediately
    }
}

void setup_signal_handlers() {
    signal(SIGINT, signal_handler);  // Ctrl+C
    signal(SIGTERM, signal_handler); // Termination signal
}

void truncate_log() {
    std::cout << "Truncating log..." << std::endl;
    Log packet_log("packet.log", true);
    Log state_log("state.log", true);
    packet_log.truncate();
    state_log.truncate();
}

ProgramOptions parse_arguments(int argc, char* argv[]) {
    ProgramOptions options;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 < argc) {
                options.filter = argv[++i];  // Set filter to the next argument
            } else {
                std::cerr << "Error: -f requires a filter string." << std::endl;
                exit(1);
            }
        }
        else if (strcmp(argv[i], "-D") == 0) {
            options.debug_mode = true;
            truncate_log();
        }     
        else if (strcmp(argv[i], "-d") == 0) options.debug_mode = true;
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) options.cleanup_interval_seconds = atoi(argv[++i]);
        else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            // New option for specifying analyzers
            std::string analyzer_list = argv[++i];
            size_t pos = 0;
            while ((pos = analyzer_list.find(',')) != std::string::npos) {
                options.enabled_analyzers.push_back(analyzer_list.substr(0, pos));
                analyzer_list.erase(0, pos + 1);
            }
            if (!analyzer_list.empty()) {
                options.enabled_analyzers.push_back(analyzer_list);
            } else {
                options.enabled_analyzers = {"reassm", "tls"};  // Default to Reassm,TLS analyzer
            }
        }
    }
    return options;
}

std::vector<std::string> create_analyzers(const ProgramOptions& options) {
    std::vector<std::string> checked_analyzers;
    auto& registry = AnalyzerRegistry::get_instance();

    // Register all available analyzers
    AnalyzerRegistrar::register_default_analyzers();

    // Create dummy key for initial analyzer creation
    ConnectionKey dummy_key;

    // Create enabled analyzers
    for (const auto& analyzer_name : options.enabled_analyzers) {
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

pcap_t* initialize_pcap(const std::string& filter, char* errbuf) {
    pcap_t* handle = pcap_open_live("en1", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
        return nullptr;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return nullptr;
    }
    return handle;
}

void print_startup_message(const ProgramOptions& options) {
    std::cout << "starting tcp state tracking on en1 with filter 'tcp' (debug " <<
           std::string(options.debug_mode ? "on" : "off") <<
           ", flush every 1000 updates or 5 minutes, debounce " <<
           std::to_string(options.cleanup_interval_seconds) + " s)" << std::endl;

    std::cout << "Active analyzers:" << std::endl;
    for (const auto& name : options.enabled_analyzers) {
        std::cout << "- " << name << ": " 
                 << AnalyzerRegistry::get_instance().get_analyzer_description(name) 
                 << std::endl;
    }
}

void run_packet_capture(pcap_t* handle, PacketProcessor& processor) {
    pcap_handle = handle;  // Set global handle for signal handler
    pcap_loop(handle, 0, packet_callback, reinterpret_cast<u_char*>(&processor));
    pcap_close(handle);    // Cleanup after pcap_loop returns
    pcap_handle = nullptr; // Reset global handle
    std::cout << "Program terminated cleanly." << std::endl;
}

int main(int argc, char* argv[]) {
    ProgramOptions options = parse_arguments(argc, argv);
    setup_signal_handlers();

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = initialize_pcap(options.filter, errbuf);
    if (!handle) {
        return 1;
    }

    print_startup_message(options);
    auto checked_analyzers = create_analyzers(options);
    ConnectionManager conn_manager(options.cleanup_interval_seconds, options.debug_mode, checked_analyzers);
    PacketProcessor processor(conn_manager, options.debug_mode);
    
    run_packet_capture(handle, processor);

    return 0;
}
