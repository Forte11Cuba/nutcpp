#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>

namespace nutcpp {

// Strict hex nibble: only accepts 0-9, a-f, A-F
inline unsigned char hex_nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(10 + (c - 'a'));
    if (c >= 'A' && c <= 'F') return static_cast<unsigned char>(10 + (c - 'A'));
    throw std::invalid_argument("Invalid hex character");
}

// Hex string to bytes. Strict: rejects whitespace, signs, odd length.
inline std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("Hex string must have even length");
    std::vector<unsigned char> bytes(hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        unsigned char hi = hex_nibble(hex[i * 2]);
        unsigned char lo = hex_nibble(hex[i * 2 + 1]);
        bytes[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return bytes;
}

// Bytes to lowercase hex string.
inline std::string bytes_to_hex(const unsigned char* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result(len * 2, '0');
    for (size_t i = 0; i < len; ++i) {
        result[i * 2]     = hex_chars[data[i] >> 4];
        result[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    return result;
}

inline std::string bytes_to_hex(const std::vector<unsigned char>& data) {
    return bytes_to_hex(data.data(), data.size());
}

} // namespace nutcpp
