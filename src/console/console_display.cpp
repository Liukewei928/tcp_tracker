#include "console/console_display.hpp"
#include <iostream>
#include <iomanip>

ConsoleDisplay::ConsoleDisplay(int debounce_seconds, const std::string& startup_message)
    : debounce_seconds_(debounce_seconds), startup_message_(startup_message), 
      last_print_time_(std::chrono::steady_clock::now() - std::chrono::seconds(debounce_seconds_)),
      last_line_count_(0) {}

void ConsoleDisplay::update_connections(const std::deque<Connection*>& connections) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_print_time_).count();
    if (elapsed >= debounce_seconds_) {
        print_table(connections);
        last_print_time_ = now;
    }
}

void ConsoleDisplay::print_table(const std::deque<Connection*>& connections) const {
    // Move cursor up to overwrite previous output
    if (last_line_count_ > 0) {
        std::cout << "\033[" << last_line_count_ << "A";
    }

    // Print header
    std::cout << startup_message_ << "\n";
    std::cout << "Latest 10 Active TCP Connections:\n";
    std::cout << std::left
              << std::setw(ID_WIDTH) << "ID" 
              << std::setw(ADDR_WIDTH) << "SRC" 
              << std::setw(ADDR_WIDTH) << "DST" 
              << std::setw(STATE_WIDTH) << "State" << "\n";
    std::cout << std::string(ID_WIDTH + 2 * ADDR_WIDTH + STATE_WIDTH, '-') << "\n";

    // Print connections
    auto now = std::chrono::steady_clock::now();
    int lines_printed = 4;  // Header lines
    for (size_t i = 0; i < connections.size() && i < 10; ++i) {
        const auto* conn = connections[i];
        const auto& key = conn->get_key();
        std::cout << std::setw(ID_WIDTH) << conn->get_id()
                  << std::setw(ADDR_WIDTH) << (key.src_ip + ":" + std::to_string(key.src_port))
                  << std::setw(ADDR_WIDTH) << (key.dst_ip + ":" + std::to_string(key.dst_port))
                  << std::setw(STATE_WIDTH) << std::left << conn->get_current_state(now) << "\n";
        ++lines_printed;
    }

    // Overwrite any remaining lines from previous output
    while (lines_printed < last_line_count_) {
        std::cout << std::string(ID_WIDTH + 2 * ADDR_WIDTH + STATE_WIDTH, ' ') << "\n";
        ++lines_printed;
    }

    std::cout << std::flush;
    last_line_count_ = lines_printed;
}
