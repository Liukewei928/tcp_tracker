#ifndef CONNECTION_HPP
#define CONNECTION_HPP

#include "tcp/tcp_state.hpp"
#include "log/log.hpp"
#include <string>
#include <chrono>
#include <functional>  // For std::hash

struct ConnectionKey {
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;

    ConnectionKey() : src_ip(""), src_port(0), dst_ip(""), dst_port(0) {}
    ConnectionKey(const std::string& src_ip_, uint16_t src_port_, const std::string& dst_ip_, uint16_t dst_port_);
    bool operator<(const ConnectionKey& other) const;
    bool operator==(const ConnectionKey& other) const;
	const ConnectionKey& operator!() const;
};

// Hash specialization for ConnectionKey
namespace std {
    template<>
    struct hash<ConnectionKey> {
        std::size_t operator()(const ConnectionKey& key) const {
            std::size_t h1 = std::hash<std::string>{}(key.src_ip);
            std::size_t h2 = std::hash<uint16_t>{}(key.src_port);
            std::size_t h3 = std::hash<std::string>{}(key.dst_ip);
            std::size_t h4 = std::hash<uint16_t>{}(key.dst_port);
            // Combine hashes (simple but effective method)
            return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
        }
    };
}

class Connection {
public:
    Connection(const ConnectionKey& key, int id);

    void update_client_state(uint8_t flags);
    void update_server_state(uint8_t flags);
    std::string get_state_change_info(std::chrono::steady_clock::time_point now) const;
    tcp_state get_client_state() const { return client_state_.state;};
	tcp_state get_server_state() const { return server_state_.state;};
   
	bool should_clean_up() const;
	bool is_from_client(const std::string& pkt_src_ip) const;

    const ConnectionKey& get_key() const { return key_; }
    int get_id() const { return id_; }

    void truncate_state_log();

private:
	tcp_state determine_new_client_state(tcp_state current, uint8_t flags);
	tcp_state determine_new_server_state(tcp_state current, uint8_t flags);

    struct State {
        tcp_state state = tcp_state::closed;
 		tcp_state prev_state = tcp_state::closed;
        std::chrono::steady_clock::time_point start_time;
    };
	static constexpr std::chrono::seconds TIME_WAIT_DURATION{30};

    ConnectionKey key_;
    int id_;
    State client_state_;
    State server_state_;
    std::chrono::steady_clock::time_point last_update_;
    
    Log state_log_;
};

#endif // CONNECTION_HPP
