#ifndef ARGS_PARSER_HPP
#define ARGS_PARSER_HPP

#include <string>
#include <vector>

struct ProgramOptions {
    bool debug_mode = false;
    bool truncate_log = false;
    int cleanup_interval_seconds = 5; // This can affect program exit waiting time.
    std::string filter = "tcp";
    std::vector<std::string> enabled_analyzers;
    std::vector<std::string> enabled_print_out_logs;
};

void check_default_argments(ProgramOptions& options);
void parse_extra_arguments(const std::string& to_parse, std::vector<std::string>& output);
void parse_filter_arguments(int argc, char* argv[], int& i, ProgramOptions& options);
void parse_log_arguments(int argc, char* argv[], int& i, ProgramOptions& options);
void parse_tcp_arguments(int argc, char* argv[], int& i, ProgramOptions& options);
void parse_reassm_arguments(int argc, char* argv[], int& i, ProgramOptions& options);
ProgramOptions parse_arguments(int argc, char* argv[]);
void print_parsed_message(const ProgramOptions& options);

#endif // ARGS_PARSER_HPP
