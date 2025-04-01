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
    bool operator==(const ConnectionKey& other) const;
    bool operator!=(const ConnectionKey& other) const;
	const ConnectionKey& operator!() const;
};

// --- Hash Specialization for ConnectionKey (Bi-directional aware) ---
namespace std {
    template<>
    struct hash<ConnectionKey> {
        std::size_t operator()(const ConnectionKey& key) const {
            // Combine hashes in a way that is order-independent for the two endpoints.
            // Method: Hash each endpoint (IP+Port) pair separately, then combine using XOR.
            // XOR is commutative (a ^ b == b ^ a), ensuring order independence.

            std::hash<std::string> string_hasher;
            std::hash<uint16_t> port_hasher;

            // Hash endpoint 1 (src)
            // Combine ip and port hash - using a simple shift/XOR combo
            std::size_t src_hash = string_hasher(key.src_ip) ^ (port_hasher(key.src_port) << 1);

            // Hash endpoint 2 (dst)
            std::size_t dst_hash = string_hasher(key.dst_ip) ^ (port_hasher(key.dst_port) << 1);

            // Combine the two endpoint hashes using XOR.
            // The order of src_hash and dst_hash doesn't matter due to XOR.
        	return src_hash ^ dst_hash;
		}
	};
}

class Connection {
public:
    Connection(const ConnectionKey& key, int id, bool debug_mode = false);
	~Connection();

    void update_client_state(uint8_t flags);
    void update_server_state(uint8_t flags);
    std::string get_state_change_info(std::chrono::steady_clock::time_point now) const;
    tcp_state get_client_state() const { return client_state_.state;};
	tcp_state get_server_state() const { return server_state_.state;};
   
	bool should_clean_up() const;
	bool is_from_client(const std::string& pkt_src_ip) const;

    const ConnectionKey& get_key() const { return key_; }
    int get_id() const { return id_; }

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
	bool debug_mode_;
};

#endif // CONNECTION_HPP
