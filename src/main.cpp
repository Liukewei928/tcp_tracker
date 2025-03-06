#include "packet_processor.hpp"
#include "console_display.hpp"
#include "log_recorder.hpp"
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <signal.h>

struct args {
    const char* filter_exp = "tcp";
    bool debug_mode = false;
    bool state_log_mode = false;
    int flush_updates = 1000;
    int flush_minutes = 5;
    int debounce_seconds = 5;
    int cleanup_interval_seconds = 5;
};

// Global pointer to LogRecorder for signal handling
static LogRecorder* g_logger = nullptr;

void signal_handler(int signum) {
    if (g_logger) {
        g_logger->flush_state_log();
    }
    exit(signum);
}

void print_usage(const char* prog_name) {
    std::cerr << "Usage: " << prog_name << " [-f \"filter\"] [-d] [-s] [-n updates] [-m minutes] [-t debounce] [-c cleanup]" << std::endl;
}

static void parse_string_arg(const char* arg, const char* next, const char*& target, const char* err_msg, const char* prog_name) {
    if (next) target = next;
    else { std::cerr << err_msg << std::endl; print_usage(prog_name); exit(1); }
}

static void parse_int_arg(const char* arg, const char* next, int& target, const char* err_msg, const char* prog_name) {
    if (next) target = std::atoi(next);
    else { std::cerr << err_msg << std::endl; print_usage(prog_name); exit(1); }
}

args parse_args(int argc, char* argv[]) {
    args result;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0) {
            parse_string_arg(argv[i], i + 1 < argc ? argv[++i] : nullptr, result.filter_exp, "Error: -f requires a filter", argv[0]);
        } else if (strcmp(argv[i], "-d") == 0) {
            result.debug_mode = true;
        } else if (strcmp(argv[i], "-s") == 0) {
            result.state_log_mode = true;
        } else if (strcmp(argv[i], "-n") == 0) {
            parse_int_arg(argv[i], i + 1 < argc ? argv[++i] : nullptr, result.flush_updates, "Error: -n requires a number", argv[0]);
        } else if (strcmp(argv[i], "-m") == 0) {
            parse_int_arg(argv[i], i + 1 < argc ? argv[++i] : nullptr, result.flush_minutes, "Error: -m requires a number", argv[0]);
        } else if (strcmp(argv[i], "-t") == 0) {
            parse_int_arg(argv[i], i + 1 < argc ? argv[++i] : nullptr, result.debounce_seconds, "Error: -t requires a number", argv[0]);
        } else if (strcmp(argv[i], "-c") == 0) {
            parse_int_arg(argv[i], i + 1 < argc ? argv[++i] : nullptr, result.cleanup_interval_seconds, "Error: -c requires a number", argv[0]);
        } else {
            std::cerr << "Unknown argument: " << argv[i] << std::endl;
            print_usage(argv[0]);
            exit(1);
        }
    }
    return result;
}

pcap_t* open_pcap_device(const char* dev, char* errbuf) {
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) std::cerr << "couldn't open device " << dev << ": " << errbuf << std::endl;
    return handle;
}

bool set_pcap_filter(pcap_t* handle, const char* filter_exp) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        return false;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* dev = "en1";

    auto args = parse_args(argc, argv);

    std::ostringstream oss;
    oss << "starting tcp state tracking on " << dev << " with filter '" << args.filter_exp 
        << "' (debug " << (args.debug_mode ? "on" : "off") << ", state log " 
        << (args.state_log_mode ? "on" : "off") << ", flush every " << args.flush_updates 
        << " updates or " << args.flush_minutes << " minutes, debounce " << args.debounce_seconds 
        << " s, cleanup every " << args.cleanup_interval_seconds << " s)";

    pcap_t* handle = open_pcap_device(dev, errbuf);
    if (!handle) return 1;

    if (!set_pcap_filter(handle, args.filter_exp)) {
        pcap_close(handle);
        return 1;
    }

    signal(SIGINT, signal_handler);  // Register signal handler for Ctrl+C
    ConsoleDisplay display(args.debounce_seconds, oss.str());
    LogRecorder logger(args.debug_mode, args.state_log_mode, args.flush_updates, args.flush_minutes);
    g_logger = &logger;  // Set global pointer for signal handler
    PacketProcessor processor(display, logger, args.cleanup_interval_seconds);
    pcap_loop(handle, 0, packet_callback, reinterpret_cast<u_char*>(&processor));
    g_logger = nullptr;  // Clear pointer on normal exit

    pcap_close(handle);
    return 0;
}
