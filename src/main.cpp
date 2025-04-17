#include "tcp/packet_processor.hpp"
#include "tcp/connection_manager.hpp"
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
    }
    return options;
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

std::string create_startup_message(const ProgramOptions& options) {
    return "starting tcp state tracking on en1 with filter 'tcp' (debug " +
           std::string(options.debug_mode ? "on" : "off") +
           ", flush every 1000 updates or 5 minutes, debounce " +
           std::to_string(options.cleanup_interval_seconds) + " s)";
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

    std::cout << create_startup_message(options) << std::endl;
    
    // Create connection manager first
    ConnectionManager conn_manager(options.cleanup_interval_seconds, options.debug_mode);
    
    // Create packet processor with reference to connection manager
    PacketProcessor processor(conn_manager, options.debug_mode);
    
    run_packet_capture(handle, processor);

    return 0;
}
