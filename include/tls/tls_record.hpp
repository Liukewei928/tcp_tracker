#ifndef TLS_RECORD_HPP
#define TLS_RECORD_HPP

#include "definations/tls_types.hpp"
#include <vector>
#include <optional>

class TLSRecord {
public:
    // Parse a TLS record from raw data
    // Returns bytes consumed if successful, 0 if more data needed
    static std::optional<size_t> try_parse(const uint8_t* data, size_t len, 
                                         TLSContentType& type, std::vector<uint8_t>& fragment);

    // Validate a potential TLS record header
    static bool validate_header(const uint8_t* data, size_t len);

private:
    static bool check_version(uint16_t version);
    static bool check_length(uint16_t length);
};

class TLSBuffer {
public:
    // Add new data to the buffer
    void add_data(const uint8_t* data, size_t len);
    
    // Try to extract a complete TLS record
    // Returns true if a record was extracted
    bool try_extract_record(TLSContentType& type, std::vector<uint8_t>& fragment);
    
    // Clear the buffer state
    void reset();

private:
    std::vector<uint8_t> buffer_;
};

#endif // TLS_RECORD_HPP
