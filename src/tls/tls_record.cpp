#include "tls/tls_record.hpp"
#include <algorithm>
#include <iostream>

std::optional<size_t> TLSRecord::try_parse(const uint8_t* data, size_t len,
                                         TLSContentType& type, std::vector<uint8_t>& fragment) {
    if (!validate_header(data, len)) {
        std::cout << "[TLSRecord] Invalid header: insufficient data\n";
        return std::nullopt;
    }

    // Parse header fields
    type = static_cast<TLSContentType>(data[0]);
    uint16_t version = (data[1] << 8) | data[2];
    uint16_t length = (data[3] << 8) | data[4];

    // Validate version and length
    if (!check_version(version) || !check_length(length)) {
        std::cout << "[TLSRecord] Invalid version or length: version = " << std::hex << version << ", length = " << length << "\n";
        return std::nullopt;
    }

    // Check if we have the complete record
    size_t total_length = TLS_RECORD_HEADER_LEN + length;
    if (len < total_length) {
        std::cout << "[TLSRecord] Incomplete record: need " << total_length << " bytes, have " << len << "\n";
        return std::nullopt;
    }

    // Extract fragment
    fragment.assign(data + TLS_RECORD_HEADER_LEN, data + total_length);
    std::cout << "[TLSRecord] Successfully parsed record: type = " << static_cast<int>(type) << ", length = " << length << "\n";
    return total_length;
}

bool TLSRecord::validate_header(const uint8_t* data, size_t len) {
    return len >= TLS_RECORD_HEADER_LEN;
}

bool TLSRecord::check_version(uint16_t version) {
    // Accept all known TLS versions
    switch (version) {
        case static_cast<uint16_t>(TLSVersion::TLS_1_0):
        case static_cast<uint16_t>(TLSVersion::TLS_1_1):
        case static_cast<uint16_t>(TLSVersion::TLS_1_2):
        case static_cast<uint16_t>(TLSVersion::TLS_1_3):
            return true;
        default:
            return false;
    }
}

bool TLSRecord::check_length(uint16_t length) {
    return length <= TLS_MAX_RECORD_LEN;
}

void TLSBuffer::add_data(const uint8_t* data, size_t len) {
    buffer_.insert(buffer_.end(), data, data + len);
}

bool TLSBuffer::try_extract_record(TLSContentType& type, std::vector<uint8_t>& fragment) {
    if (buffer_.empty()) {
        return false;
    }

    auto result = TLSRecord::try_parse(buffer_.data(), buffer_.size(), type, fragment);
    if (!result) {
        return false;
    }

    // Remove the processed record from the buffer
    buffer_.erase(buffer_.begin(), buffer_.begin() + *result);
    return true;
}

void TLSBuffer::reset() {
    buffer_.clear();
}
