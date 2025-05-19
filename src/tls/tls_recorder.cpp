#include "tls/tls_recorder.hpp"
#include "log/conn_log_entry.hpp"
#include <algorithm>
#include <iostream>
#include <iomanip>

TLSRecorder::TLSRecorder(std::function<void(const std::string&)> log_helper)
    : log_helper_(std::move(log_helper)) {
}

std::optional<size_t> TLSRecorder::try_parse(const uint8_t* data, size_t len,
    TLSContentType& type, std::vector<uint8_t>& fragment) {
    std::ostringstream oss;
    if (!validate_header(data, len)) {
        oss << "[TLSRecorder] Invalid header: insufficient data";
        log_helper_(oss.str());
        return std::nullopt;
    }

    // Parse header fields
    type = static_cast<TLSContentType>(data[0]);
    uint16_t version = (data[1] << 8) | data[2];
    uint16_t length = (data[3] << 8) | data[4];

    // Validate version and length
    if (!check_version(version) || !check_length(length)) {
        oss << "[TLSRecorder] Invalid version or length: version = " 
            << std::hex << version << ", length = " << length << std::endl;
        oss << "[TLSRecorder] Raw header bytes with len " << std::dec << len << ":" << std::endl;
        oss << LogEntry::get_formatted_buffer(data, len);
        log_helper_(oss.str());
        return std::nullopt;
    }

    // Check if we have the complete record
    size_t total_length = TLS_RECORD_HEADER_LEN + length;
    if (len < total_length) {
        oss << "[TLSRecorder] Incomplete record: need " << total_length << " bytes, have " << len;
        log_helper_(oss.str());
        return std::nullopt;
    }

    // Extract fragment
    fragment.assign(data + TLS_RECORD_HEADER_LEN, data + total_length);
    oss << "[TLSRecorder] Fragment bytes with len " << fragment.size() << ":" << std::endl;
    oss << LogEntry::get_formatted_buffer(fragment.data(), fragment.size()) << std::endl;
    oss << "[TLSRecorder] Successfully parsed record: type = " << static_cast<int>(type)
        << " (" << get_tls_content_type_name(type) << "), length: " << fragment.size();
    log_helper_(oss.str());
    return total_length;
}

bool TLSRecorder::validate_header(const uint8_t* data, size_t len) {
    return len >= TLS_RECORD_HEADER_LEN;
}

bool TLSRecorder::check_version(uint16_t version) {
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

bool TLSRecorder::check_length(uint16_t length) {
    return length <= TLS_MAX_RECORD_LEN;
}

void TLSRecorder::add_data(const uint8_t* data, size_t len) {
    buffer_.insert(buffer_.end(), data, data + len);
}

bool TLSRecorder::try_extract_record(TLSContentType& type, std::vector<uint8_t>& fragment) {
    if (buffer_.empty()) {
        return false;
    }

    auto result = try_parse(buffer_.data(), buffer_.size(), type, fragment);
    if (!result) {
        return false;
    }

    // Remove the processed record from the buffer
    buffer_.erase(buffer_.begin(), buffer_.begin() + *result);
    return true;
}

void TLSRecorder::reset() {
    buffer_.clear();
}
