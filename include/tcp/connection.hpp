#ifndef CONNECTION_HPP
#define CONNECTION_HPP

#include "tcp/connection_key.hpp"
#include "tcp/tcp_state_machine.hpp"
#include "tcp_def/reassembly_def.hpp"
#include "tcp/reassembly.hpp"
#include "log/log.hpp"
#include <string>
#include <chrono>

class Connection {
public:
    Connection(const ConnectionKey& key, int id, bool debug_mode = false, Reassebly::DataCallback data_callback = nullptr);
	~Connection();

    void update_client_state(uint8_t flags);
    void update_server_state(uint8_t flags);
    void process_payload(bool is_from_client, uint32_t seq, const uint8_t* payload, size_t payload_len, uint8_t flags);
	bool should_clean_up() const;

    tcp_state get_client_state() const { return client_state_.state;};
    tcp_state get_server_state() const { return server_state_.state;};
	bool is_from_client(const std::string& pkt_src_ip) const { return key_.src_ip == pkt_src_ip;};
    const ConnectionKey& get_key() const { return key_; }
    int get_id() const { return id_; }

    std::string get_state_change_info(std::chrono::steady_clock::time_point now) const;

private:
	tcp_state determine_new_client_state(tcp_state current, uint8_t flags);
	tcp_state determine_new_server_state(tcp_state current, uint8_t flags);

    void handle_syn_sequence(bool is_from_client, uint32_t seq);
    void handle_reassembly(bool is_from_client, uint32_t seq, const uint8_t* payload, size_t payload_len, uint8_t flags);
    void handle_fin(bool is_from_client);
    void handle_rst();

    ConnectionKey key_;
    int id_;
    State client_state_;
    State server_state_;
    std::chrono::steady_clock::time_point last_update_;
    Log state_log_;
	bool debug_mode_;
    std::unique_ptr<Reassebly> client_reassembly_;
    std::unique_ptr<Reassebly> server_reassembly_;
    TcpStateMachine state_machine_;
};

#endif // CONNECTION_HPP
