#include "main/args_parser.hpp"
#include <iostream>

void check_default_argments(ProgramOptions& options)
{
    if (options.enabled_analyzers.empty()) {
        options.enabled_analyzers = {"reassm", "tls"};
    }
}

void parse_extra_arguments(const std::string& to_parse, std::vector<std::string>& output)
{
    std::string trimmable = to_parse;
    size_t pos = 0;
    while ((pos = trimmable.find(',')) != std::string::npos) {
        output.push_back(trimmable.substr(0, pos));
        trimmable.erase(0, pos + 1);
    }
    if (!trimmable.empty()) {
        output.push_back(trimmable);
    }
}

void parse_filter_arguments(int argc, char* argv[], int& i, ProgramOptions& options) {
    if (strcmp(argv[i], "-f") == 0) {
        if (i + 1 < argc) {
            options.filter = argv[++i];
        } else {
            std::cerr << "Error: -f requires a filter string" << std::endl;
            exit(1);
        }
    }
}

void parse_log_arguments(int argc, char* argv[], int& i, ProgramOptions& options) {
    if (strcmp(argv[i], "-D") == 0) {
        options.debug_mode = true;
        options.truncate_log = true;
        if (i + 1 < argc && argv[i + 1][0] != '-') {
            parse_extra_arguments(std::string(argv[++i]), options.enabled_print_out_logs);
        }
    } else if (strcmp(argv[i], "-d") == 0) {
        options.debug_mode = true;
        if (i + 1 < argc && argv[i + 1][0] != '-') {
            parse_extra_arguments(std::string(argv[++i]), options.enabled_print_out_logs);
        }
    }
}

void parse_tcp_arguments(int argc, char* argv[], int& i, ProgramOptions& options) {
    if (strcmp(argv[i], "-c") == 0) {
        if (i + 1 < argc) {
            options.cleanup_interval_seconds = atoi(argv[++i]);
        } else {
            std::cerr << "Error: -c requires an integer" << std::endl;
            exit(1);
        }
    }
}

void parse_reassm_arguments(int argc, char* argv[], int& i, ProgramOptions& options) {
    if (strcmp(argv[i], "-a") == 0) {
        if (i + 1 < argc) {
            parse_extra_arguments(std::string(argv[++i]), options.enabled_analyzers);
        } else {
            std::cerr << "Error: -a requires analyzers string split with ','" << std::endl;
            exit(1);
        }
    }
}

ProgramOptions parse_arguments(int argc, char* argv[]) {
    ProgramOptions options;

    for (int i = 1; i < argc; ++i) {
        parse_filter_arguments(argc, argv, i, options);
        parse_log_arguments(argc, argv, i, options);
        parse_reassm_arguments(argc, argv, i, options);
    }
    check_default_argments(options);
    
    print_parsed_message(options);
    return options;
}

void print_parsed_message(const ProgramOptions& options) {
    std::cout << "Starting tcp state tracking on en1 with filter " << options.filter << 
        ", debug " << std::string(options.debug_mode ? "on" : "off") << 
        ", flush every 1000 updates or 5 minutes, debounce " <<
        std::to_string(options.cleanup_interval_seconds) + " s" << std::endl;

    std::cout << "Active analyzers:" << std::endl;
    for (const auto& name : options.enabled_analyzers) {
        std::cout << name << std::endl;
    }

    std::cout << "Active print out modules:" << std::endl;
    for (const auto& name : options.enabled_print_out_logs) {
        std::cout << name << std::endl;
    }
}