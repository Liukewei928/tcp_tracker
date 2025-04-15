#include "tcp/connection_key.hpp"
#include <functional>

ConnectionKey::ConnectionKey(const std::string& src_ip_, uint16_t src_port_, const std::string& dst_ip_, uint16_t dst_port_)
    : src_ip(src_ip_), src_port(src_port_), dst_ip(dst_ip_), dst_port(dst_port_) {
}

// Comparison operator: checks direct and reverse match
bool ConnectionKey::operator==(const ConnectionKey& other) const {
    bool direct_match = (src_ip == other.src_ip &&
                         src_port == other.src_port &&
                         dst_ip == other.dst_ip &&
                         dst_port == other.dst_port);

    bool reverse_match = (src_ip == other.dst_ip &&
                          src_port == other.dst_port &&
                          dst_ip == other.src_ip &&
                          dst_port == other.src_port);

    return direct_match || reverse_match;
}

bool ConnectionKey::operator!=(const ConnectionKey& other) const {
    return !(*this == other);
}

// Returns a key representing the opposite direction (by value)
ConnectionKey ConnectionKey::operator!() const {
    return ConnectionKey(this->dst_ip, this->dst_port, this->src_ip, this->src_port);
}

std::size_t std::hash<ConnectionKey>::operator()(const ConnectionKey& key) const {        
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
