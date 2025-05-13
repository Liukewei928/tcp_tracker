#include "main/args_parser.hpp"
#include "main/pcap_handler.hpp"
#include "conn/packet_processor.hpp"
#include "conn/connection_manager.hpp"  
#include "reassm/analyzer_registrar.hpp"
#include "log/log_manager.hpp"
#include <iostream>
#include <cstring>

// Global variables for signal handling
static std::atomic<bool> running(true);
static pcap_t* pcap_handle = nullptr;

void signal_handler(int signum) {
    std::cout << "Received signal " << signum << std::endl;
    running = false;
    if (pcap_handle) {
        pcap_breakloop(pcap_handle);
    }
}

void setup_signal_handlers() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
}

int main(int argc, char* argv[]) {
    ProgramOptions options = parse_arguments(argc, argv);

    pcap_t* handle = initialize_pcap(options.filter);
    if (!handle) {
        std::cerr << "Initialize pcap failed" << std::endl;
        return -1;
    }

    if(!LogManager::get_instance().init(
        options.debug_mode, options.truncate_log, options.enabled_print_out_logs))
    {
        std::cerr << "Initialize log failed" << std::endl;
        return -1;    
    }

    ConnectionManager conn_manager(options.cleanup_interval_seconds, 
        AnalyzerRegistrar::create_analyzers(options.enabled_analyzers));
    PacketProcessor processor(conn_manager);

    setup_signal_handlers();
    pcap_handle = handle;  // Set global handle for signal handler
    run_packet_capture(handle, reinterpret_cast<u_char*>(&processor));
    pcap_handle = nullptr; // Reset global handle

    return 0;
}
