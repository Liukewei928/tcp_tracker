#ifndef CONNECTION_HPP
#define CONNECTION_HPP

#include <chrono>
#include <string>
#include "tcp_state.hpp"

struct ConnectionKey {
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;

    ConnectionKey() = default;  // Add default constructor
    ConnectionKey(const std::string& src_ip_, uint16_t src_port_, const std::string& dst_ip_, uint16_t dst_port_);
    ConnectionKey normalized() const;
    bool operator<(const ConnectionKey& other) const;
    bool operator==(const ConnectionKey& other) const;
};

namespace std {
    template<> struct hash<ConnectionKey> {
        std::size_t operator()(const ConnectionKey& k) const {
            return ((std::hash<std::string>()(k.src_ip) ^ (std::hash<uint16_t>()(k.src_port) << 1)) >> 1) ^
                   ((std::hash<std::string>()(k.dst_ip) ^ (std::hash<uint16_t>()(k.dst_port) << 1)));
        }
    };
}

class Connection {
public:
    Connection(const ConnectionKey& key, int id);
    tcp_state get_client_state() const { return client_state_.state; }
    tcp_state get_server_state() const { return server_state_.state; }
    const ConnectionKey& get_key() const { return key_; }
    int get_id() const { return id_; }
    void update_state_client(uint8_t flags, std::chrono::steady_clock::time_point timestamp);
    void update_state_server(uint8_t flags, std::chrono::steady_clock::time_point timestamp);
    bool should_clean_up() const;
    std::string get_current_state(std::chrono::steady_clock::time_point now) const;
    std::string get_current_state_name() const;

private:
    struct state_info {
        tcp_state state = tcp_state::closed;
        std::chrono::steady_clock::time_point start_time;
    };

    void update_state(state_info& info, uint8_t flags, bool is_client, std::chrono::steady_clock::time_point timestamp);

    ConnectionKey key_;
    int id_;
    state_info client_state_;
    state_info server_state_;
    std::chrono::steady_clock::time_point last_update_;
    static constexpr std::chrono::seconds TIME_WAIT_DURATION{120};
};

tcp_state determine_new_state(tcp_state current, uint8_t flags, bool is_client);

#endif // CONNECTION_HPP
