#ifndef CONNECTION_KEY_HPP
#define CONNECTION_KEY_HPP

#include <string>
#include <cstdint>
#include <optional>

struct ConnectionKey {
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;

    ConnectionKey() : src_ip(""), src_port(0), dst_ip(""), dst_port(0) {}
    ConnectionKey(const std::string& src_ip_, uint16_t src_port_, const std::string& dst_ip_, uint16_t dst_port_);
    bool operator==(const ConnectionKey& other) const;
    bool operator!=(const ConnectionKey& other) const;
	ConnectionKey operator!() const;
};

namespace std {
    template <>
    struct hash<ConnectionKey> {
        std::size_t operator()(const ConnectionKey& k) const;
    };
}

#endif // CONNECTION_KEY_HPP    