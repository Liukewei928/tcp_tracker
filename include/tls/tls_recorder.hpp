#ifndef TLS_RECORDER_HPP
#define TLS_RECORDER_HPP

#include "definitions/tls_types.hpp"
#include <functional>
#include <string>
#include <vector>
#include <optional>

class TLSRecorder {
public:
    explicit TLSRecorder(std::function<void(const std::string&)> log_helper);
 
    void add_data(const uint8_t* data, size_t len);

    // Try to extract a complete TLS record from the buffer
    // Returns true if a record was extracted
    bool try_extract_record(TLSContentType& type, std::vector<uint8_t>& fragment);
    void reset();

private:
    // Parse a TLS record from raw data
    // Returns bytes consumed if successful, 0 if more data needed
    std::optional<size_t> try_parse(const uint8_t* data, size_t len, 
        TLSContentType& type, std::vector<uint8_t>& fragment);

    bool validate_header(const uint8_t* data, size_t len);
    bool check_version(uint16_t version);
    bool check_length(uint16_t length);

    std::vector<uint8_t> buffer_;
    std::function<void(const std::string&)> log_helper_;
};

#endif // TLS_RECORDER_HPP
