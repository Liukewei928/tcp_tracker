#ifndef TLS_TYPES_HPP
#define TLS_TYPES_HPP

#include <cstdint>
#include <cstddef>

// TLS protocol version numbers
enum class TLSVersion : uint16_t {
    TLS_1_0 = 0x0301,
    TLS_1_1 = 0x0302,
    TLS_1_2 = 0x0303,
    TLS_1_3 = 0x0304
};

// TLS record layer content types
enum class TLSContentType : uint8_t {
    CHANGE_CIPHER_SPEC = 20,  // Change cipher spec message
    ALERT = 21,               // Alert message
    HANDSHAKE = 22,          // Handshake message
    APPLICATION_DATA = 23     // Application data
};

// TLS handshake protocol message types
enum class TLSHandshakeType : uint8_t {
    CLIENT_HELLO = 1,         // Initial client message
    SERVER_HELLO = 2,         // Server response to client hello
    CERTIFICATE = 11,         // Certificate message
    KEY_EXCHANGE = 12,        // Server's key material
    FINISHED = 20            // Final handshake message
};

// TLS connection state
enum class TLSState {
    INIT,                    // Initial state
    HANDSHAKE_STARTED,       // First handshake message sent/received
    NEGOTIATING,            // Handshake messages being exchanged
    HANDSHAKE_DONE,          // Handshake completed successfully
    ERROR                   // Error occurred during processing
};

// TLS protocol constants
inline constexpr size_t TLS_RECORD_HEADER_LEN = 5;
inline constexpr size_t TLS_MAX_RECORD_LEN = 16384;

#endif // TLS_TYPES_HPP
