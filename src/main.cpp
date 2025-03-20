#include "tcp/packet_processor.hpp"
#include "console/console_display.hpp"
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <thread>
#include <csignal>
#include <atomic>

// Global variables for signal handling
static std::atomic<bool> running(true);
static PacketProcessor* processor_ptr = nullptr;
static pcap_t* pcap_handle = nullptr;  // Added to allow signal handler to break pcap_loop

struct ProgramOptions {
    bool state_log_mode = false;
    bool debug_mode = false;
    bool truncate_packet_log = false;
    bool truncate_state_log = false;
    int debounce_seconds = 5;
    int cleanup_interval_seconds = 5;
};

void signal_handler(int signum) {
    std::cout << "Received signal " << signum << ", flushing state log and exiting..." << std::endl;
    if (processor_ptr) {
        processor_ptr->flush_state_log();
    }
    running = false;
    if (pcap_handle) {
        pcap_breakloop(pcap_handle);  // Break the pcap_loop immediately
    }
}

ProgramOptions parse_arguments(int argc, char* argv[]) {
    ProgramOptions options;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-s") == 0) options.state_log_mode = true;
        else if (strcmp(argv[i], "-d") == 0) options.debug_mode = true;
        else if (strcmp(argv[i], "-D") == 0) options.truncate_packet_log = true;
        else if (strcmp(argv[i], "-S") == 0) options.truncate_state_log = true;
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) options.debounce_seconds = atoi(argv[++i]);
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) options.cleanup_interval_seconds = atoi(argv[++i]);
    }
    return options;
}

void setup_signal_handlers() {
    signal(SIGINT, signal_handler);  // Ctrl+C
    signal(SIGTERM, signal_handler); // Termination signal
}

pcap_t* initialize_pcap(char* errbuf) {
    pcap_t* handle = pcap_open_live("en1", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
        return nullptr;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return nullptr;
    }
    return handle;
}

std::string create_startup_message(const ProgramOptions& options) {
    return "starting tcp state tracking on en1 with filter 'tcp' (debug " +
           std::string(options.debug_mode ? "on" : "off") + ", state log " +
           std::string(options.state_log_mode ? "on" : "off") +
           ", flush every 1000 updates or 5 minutes, debounce " +
           std::to_string(options.debounce_seconds) + " s, cleanup every " +
           std::to_string(options.cleanup_interval_seconds) + " s)";
}

void apply_truncate_options(PacketProcessor& processor, const ProgramOptions& options) {
    if (options.truncate_packet_log) {
        std::cout << "Truncating packets.log..." << std::endl;
        processor.truncate_packet_log();
    }
    if (options.truncate_state_log) {
        std::cout << "Truncating states.log..." << std::endl;
        processor.truncate_state_log();
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
    pcap_t* handle = initialize_pcap(errbuf);
    if (!handle) {
        return 1;
    }

    std::string startup_message = create_startup_message(options);
    ConsoleDisplay display(options.debounce_seconds, startup_message);
    PacketProcessor processor(display, options.cleanup_interval_seconds);
    processor_ptr = &processor;

    apply_truncate_options(processor, options);
    run_packet_capture(handle, processor);

    return 0;
}
