#ifndef CONSOLE_DISPLAY_HPP
#define CONSOLE_DISPLAY_HPP

#include <deque>
#include <chrono>
#include "connection.hpp"

class ConsoleDisplay {
public:
    ConsoleDisplay(int debounce_seconds = 5, const std::string& startup_message = "");
    void update_connections(const std::deque<Connection*>& connections);
    static constexpr size_t STATE_WIDTH = 30;

private:
    void print_table(const std::deque<Connection*>& connections) const;

    int debounce_seconds_;
    std::string startup_message_;
    mutable std::chrono::steady_clock::time_point last_print_time_;
};

#endif // CONSOLE_DISPLAY_HPP
