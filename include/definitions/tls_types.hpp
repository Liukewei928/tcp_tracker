#ifndef TLS_TYPES_HPP
#define TLS_TYPES_HPP

#include <string>
#include <vector>
#include <cstdint>

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
    APPLICATION_DATA = 23,   // Application data
    HEARTBEAT = 24  // Optional, for RFC 6520 support
};

// TLS handshake protocol message types (RFC 5246 and RFC 8446)
enum class TLSHandshakeType : uint8_t {
    HELLO_REQUEST = 0,
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    HELLO_VERIFY_REQUEST = 3,
    NEW_SESSION_TICKET = 4,
    END_OF_EARLY_DATA = 5,       // TLS 1.3
    ENCRYPTED_EXTENSIONS = 8,    // TLS 1.3
    CERTIFICATE = 11,
    SERVER_KEY_EXCHANGE = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE = 14,
    CERTIFICATE_VERIFY = 15,
    CLIENT_KEY_EXCHANGE = 16,
    FINISHED = 20,
    KEY_UPDATE = 24,             // TLS 1.3
    MESSAGE_HASH = 254           // TLS 1.3 internal use
};

// TLS connection state
enum class TLS12State {
    INIT,                       // Connection initialized
    
    // Client -> Server
    CLIENT_HELLO_SENT,          // ClientHello sent (required)
    
    // Server -> Client
    SERVER_HELLO_RECEIVED,      // ServerHello received (required)
    CERTIFICATE_RECEIVED,       // Server Certificate received (optional)
    SERVER_KEY_EXCHANGE_RECEIVED, // ServerKeyExchange received (optional)
    CERTIFICATE_REQUEST_RECEIVED, // CertificateRequest received (optional)
    SERVER_HELLO_DONE_RECEIVED,   // ServerHelloDone received (required)
    
    // Client -> Server
    CERTIFICATE_SENT,           // Client Certificate sent (if requested)
    CERTIFICATE_VERIFY_SENT,    // CertificateVerify sent (if certificate was sent)
    CLIENT_KEY_EXCHANGE_SENT,   // ClientKeyExchange sent (required)
    CHANGE_CIPHER_SPEC_SENT,    // ChangeCipherSpec sent (required)
    FINISHED_SENT,              // Finished message sent (required)
    
    // Server -> Client
    CHANGE_CIPHER_SPEC_RECEIVED,// ChangeCipherSpec received (required)
    FINISHED_RECEIVED,          // Finished message received (required)
    
    HANDSHAKE_COMPLETE,         // Full handshake complete
    ERROR                       // Error occurred during processing
};

enum class TLS13State {
    INIT,
    CLIENT_HELLO_SENT,
    SERVER_HELLO_RECEIVED,
    ENCRYPTED_EXTENSIONS_RECEIVED,
    CERTIFICATE_RECEIVED,
    CERTIFICATE_VERIFY_RECEIVED,
    FINISHED_RECEIVED,
    CLIENT_CERTIFICATE_SENT,
    CLIENT_CERTIFICATE_VERIFY_SENT,
    CLIENT_FINISHED_SENT,
    HANDSHAKE_COMPLETE,
    ERROR
};

// TLS Alert levels
enum class TLSAlertLevel : uint8_t {
    WARNING = 1,
    FATAL = 2
};

// TLS Alert descriptions
enum class TLSAlertDescription : uint8_t {
    CLOSE_NOTIFY = 0,
    UNEXPECTED_MESSAGE = 10,
    BAD_RECORD_MAC = 20,
    HANDSHAKE_FAILURE = 40,
    PROTOCOL_VERSION = 70,
    INTERNAL_ERROR = 80
};

// TLS Record Structure (RFC 5246 Section 6.2.1)
struct TLSRecord {
    TLSContentType type;
    TLSVersion version;
    uint16_t length;
    std::vector<uint8_t> fragment;
};

// TLS Alert Structure (RFC 5246 Section 7.2)
struct TLSAlert {
    TLSAlertLevel level;
    TLSAlertDescription description;
};

// TLS Change Cipher Spec Structure (RFC 5246 Section 7.1)
struct TLSChangeCipherSpec {
    static constexpr uint8_t TYPE = 1;  // always 1
    uint8_t type = TYPE;
};

// TLS Handshake Structure (RFC 5246 Section 7.4)
struct TLSHandshake {
    TLSHandshakeType type;
    uint32_t length;  // 3 bytes in protocol, but uint32_t for easier handling
    std::vector<uint8_t> message;
};

// TLS protocol constants
// Record layer constants
inline constexpr size_t TLS_RECORD_HEADER_LEN = 5;  // type(1) + version(2) + length(2)
inline constexpr size_t TLS_MAX_RECORD_LEN = 16384;
inline constexpr size_t TLS_MAX_FRAGMENT_LEN = 16384;
inline constexpr size_t TLS_MIN_RECORD_LEN = 6;     // header(5) + minimum fragment(1)

// Handshake constants
inline constexpr size_t TLS_HANDSHAKE_HEADER_LEN = 4;  // type(1) + length(3)
inline constexpr size_t TLS_MAX_HANDSHAKE_LEN = 16777215;  // 2^24 - 1

// Alert constants
inline constexpr size_t TLS_ALERT_LEN = 2;  // level(1) + description(1)
inline constexpr size_t TLS_MAX_ALERT_LEN = 2;

// Change Cipher Spec constants
inline constexpr size_t TLS_CHANGE_CIPHER_SPEC_LEN = 1;  // type(1)
inline constexpr size_t TLS_MAX_CHANGE_CIPHER_SPEC_LEN = 1;

// Version constants
inline constexpr uint16_t TLS_MAJOR_VERSION = 3;
inline constexpr uint16_t TLS_MINOR_VERSION_1_0 = 1;
inline constexpr uint16_t TLS_MINOR_VERSION_1_1 = 2;
inline constexpr uint16_t TLS_MINOR_VERSION_1_2 = 3;
inline constexpr uint16_t TLS_MINOR_VERSION_1_3 = 4;

// Content type constants
inline constexpr uint8_t TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;
inline constexpr uint8_t TLS_CONTENT_TYPE_ALERT = 21;
inline constexpr uint8_t TLS_CONTENT_TYPE_HANDSHAKE = 22;
inline constexpr uint8_t TLS_CONTENT_TYPE_APPLICATION_DATA = 23;
inline constexpr uint8_t TLS_CONTENT_TYPE_HEARTBEAT = 24;

// Alert level constants
inline constexpr uint8_t TLS_ALERT_LEVEL_WARNING = 1;
inline constexpr uint8_t TLS_ALERT_LEVEL_FATAL = 2;

// Alert description constants
inline constexpr uint8_t TLS_ALERT_CLOSE_NOTIFY = 0;
inline constexpr uint8_t TLS_ALERT_UNEXPECTED_MESSAGE = 10;
inline constexpr uint8_t TLS_ALERT_BAD_RECORD_MAC = 20;
inline constexpr uint8_t TLS_ALERT_HANDSHAKE_FAILURE = 40;
inline constexpr uint8_t TLS_ALERT_PROTOCOL_VERSION = 70;
inline constexpr uint8_t TLS_ALERT_INTERNAL_ERROR = 80;

// Helper functions for TLS content and handshake type names
static std::string get_tls_content_type_name(TLSContentType type) {
    switch (type) {
        case TLSContentType::HANDSHAKE: return "Handshake";
        case TLSContentType::ALERT: return "Alert";
        case TLSContentType::CHANGE_CIPHER_SPEC: return "ChangeCipherSpec";
        case TLSContentType::APPLICATION_DATA: return "ApplicationData";
        default: return "Unknown";
    }
}

static std::string get_tls_handshake_type_name(TLSHandshakeType type) {
    switch (type) {
        case TLSHandshakeType::HELLO_REQUEST: return "HelloRequest";
        case TLSHandshakeType::CLIENT_HELLO: return "ClientHello";
        case TLSHandshakeType::SERVER_HELLO: return "ServerHello";
        case TLSHandshakeType::HELLO_VERIFY_REQUEST: return "HelloVerifyRequest";
        case TLSHandshakeType::NEW_SESSION_TICKET: return "NewSessionTicket";
        case TLSHandshakeType::END_OF_EARLY_DATA: return "EndOfEarlyData";
        case TLSHandshakeType::ENCRYPTED_EXTENSIONS: return "EncryptedExtensions";
        case TLSHandshakeType::CERTIFICATE: return "Certificate";
        case TLSHandshakeType::SERVER_KEY_EXCHANGE: return "ServerKeyExchange";
        case TLSHandshakeType::CERTIFICATE_REQUEST: return "CertificateRequest";
        case TLSHandshakeType::SERVER_HELLO_DONE: return "ServerHelloDone";
        case TLSHandshakeType::CERTIFICATE_VERIFY: return "CertificateVerify";
        case TLSHandshakeType::CLIENT_KEY_EXCHANGE: return "ClientKeyExchange";
        case TLSHandshakeType::FINISHED: return "Finished";
        case TLSHandshakeType::KEY_UPDATE: return "KeyUpdate";
        case TLSHandshakeType::MESSAGE_HASH: return "MessageHash";
        default: return "Unknown";
    }
}



static std::string get_tls12_state_name(TLS12State state) {
    switch (state) {
        case TLS12State::INIT: return "INIT";
        case TLS12State::CLIENT_HELLO_SENT: return "CLIENT_HELLO_SENT";
        case TLS12State::SERVER_HELLO_RECEIVED: return "SERVER_HELLO_RECEIVED";
        case TLS12State::CERTIFICATE_RECEIVED: return "CERTIFICATE_RECEIVED";
        case TLS12State::SERVER_KEY_EXCHANGE_RECEIVED: return "SERVER_KEY_EXCHANGE_RECEIVED";
        case TLS12State::CERTIFICATE_REQUEST_RECEIVED: return "CERTIFICATE_REQUEST_RECEIVED";
        case TLS12State::SERVER_HELLO_DONE_RECEIVED: return "SERVER_HELLO_DONE_RECEIVED";
        case TLS12State::CERTIFICATE_SENT: return "CERTIFICATE_SENT";
        case TLS12State::CERTIFICATE_VERIFY_SENT: return "CERTIFICATE_VERIFY_SENT";
        case TLS12State::CLIENT_KEY_EXCHANGE_SENT: return "CLIENT_KEY_EXCHANGE_SENT";
        case TLS12State::CHANGE_CIPHER_SPEC_SENT: return "CHANGE_CIPHER_SPEC_SENT";
        case TLS12State::FINISHED_SENT: return "FINISHED_SENT";
        case TLS12State::CHANGE_CIPHER_SPEC_RECEIVED: return "CHANGE_CIPHER_SPEC_RECEIVED";
        case TLS12State::FINISHED_RECEIVED: return "FINISHED_RECEIVED";
        case TLS12State::HANDSHAKE_COMPLETE: return "HANDSHAKE_COMPLETE";
        case TLS12State::ERROR: return "ERROR";
        default: return "UNKNOWN_STATE";
    }
}

static std::string get_alert_description(uint8_t code) {
    switch (code) {
        case TLS_ALERT_CLOSE_NOTIFY: return "close_notify";
        case TLS_ALERT_UNEXPECTED_MESSAGE: return "unexpected_message";
        case TLS_ALERT_BAD_RECORD_MAC: return "bad_record_mac";
        case TLS_ALERT_HANDSHAKE_FAILURE: return "handshake_failure";
        case TLS_ALERT_PROTOCOL_VERSION: return "protocol_version";
        case TLS_ALERT_INTERNAL_ERROR: return "internal_error";
        default: return "unknown";
    }
}

#endif // TLS_TYPES_HPP
