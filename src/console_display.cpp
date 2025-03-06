#include "console_display.hpp"
#include <iostream>
#include <iomanip>

ConsoleDisplay::ConsoleDisplay(int debounce_seconds, const std::string& startup_message)
    : debounce_seconds_(debounce_seconds), startup_message_(startup_message), 
      last_print_time_(std::chrono::steady_clock::now() - std::chrono::seconds(debounce_seconds_)) {}

void ConsoleDisplay::update_connections(const std::deque<Connection*>& connections) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_print_time_).count();
    if (elapsed >= debounce_seconds_) {
        print_table(connections);
        last_print_time_ = now;
    }
}

void ConsoleDisplay::print_table(const std::deque<Connection*>& connections) const {
    std::cout << "\033[2J\033[1;1H";  // Clear screen and move to top
    std::cout << startup_message_ << "\n\n";
    std::cout << "Latest 10 Active TCP Connections:\n";
    std::cout << std::left
              << std::setw(5) << "ID" 
              << std::setw(25) << "SRC" 
              << std::setw(25) << "DST" 
              << std::setw(STATE_WIDTH) << "State" << "\n";
    std::cout << std::string(80, '-') << "\n";

    auto now = std::chrono::steady_clock::now();
    for (size_t i = 0; i < 10; ++i) {
        if (i < connections.size()) {
            const auto* conn = connections[i];
            const auto& key = conn->get_key();
            std::cout << std::setw(5) << conn->get_id()
                      << std::setw(25) << (key.src_ip + ":" + std::to_string(key.src_port))
                      << std::setw(25) << (key.dst_ip + ":" + std::to_string(key.dst_port))
                      << std::setw(STATE_WIDTH) << std::left << conn->get_current_state(now) << "\n";
        } else {
            std::cout << std::string(80, ' ') << "\n";
        }
    }
    std::cout << std::flush;
}
