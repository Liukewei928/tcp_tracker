#ifndef CONNECTION_HPP
#define CONNECTION_HPP

#include "conn/connection_key.hpp"
#include "conn/tcp_state_machine.hpp"
#include "reassm/reassembly.hpp"
#include "interfaces/protocol_analyzer.hpp"
#include "log/log_manager.hpp"
#include <string>
#include <chrono>

class Connection {
public:
    Connection() = default;
    Connection(const ConnectionKey& key, int id);
	~Connection();
    void add_analyzer(std::shared_ptr<IProtocolAnalyzer> analyzer);
    void update_client_state(uint8_t flags);
    void update_server_state(uint8_t flags);
    void process_payload(bool is_from_client, uint32_t seq, const uint8_t* payload, size_t payload_len, uint8_t flags);
	bool should_clean_up() const;

    TCPState get_client_state() const { return client_state_.state;};
    TCPState get_server_state() const { return server_state_.state;};
	bool is_from_client(const std::string& pkt_src_ip) const { return key_.src_ip == pkt_src_ip;};
    const ConnectionKey& get_key() const { return key_; }
    int get_id() const { return id_; }

private:
	TCPState determine_new_client_state(TCPState current, uint8_t flags);
	TCPState determine_new_server_state(TCPState current, uint8_t flags);

    void handle_syn_sequence(bool is_from_client, uint32_t seq);
    void handle_reassembly(bool is_from_client, uint32_t seq, const uint8_t* payload, size_t payload_len, uint8_t flags);
    void handle_fin(bool is_from_client);
    void handle_rst();

    ConnectionKey key_;
    int id_;
    ConnState client_state_;
    ConnState server_state_;
    std::chrono::steady_clock::time_point last_update_;
    std::unique_ptr<Reassembly> client_reassembly_;
    std::unique_ptr<Reassembly> server_reassembly_;
    TcpStateMachine state_machine_;
    Log& tcp_log_ = LogManager::get_instance().get_registered_log("tcp.log");
};

#endif // CONNECTION_HPP
