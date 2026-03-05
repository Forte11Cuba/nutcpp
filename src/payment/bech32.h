#pragma once

// Internal Bech32/Bech32m codec for NUT-26 payment requests and NIP-19 entities.
// Implements BIP-350: encode_raw/decode_raw operate on 5-bit data arrays.
// convert_bits handles 8-bit <-> 5-bit conversion.

#include <vector>
#include <string>
#include <cstdint>

namespace nutcpp {
namespace internal {

enum class Bech32Type {
    BECH32,   // constant = 1 (used by NIP-19: npub, nprofile)
    BECH32M   // constant = 0x2bc830a3 (used by NUT-26: creqB)
};

// Encode 5-bit data array to bech32/bech32m string.
// Returns lowercase string: hrp + '1' + encoded_data + checksum.
std::string bech32_encode_raw(const std::string& hrp,
                               const std::vector<uint8_t>& data_5bit,
                               Bech32Type type);

// Decode bech32/bech32m string. Returns 5-bit data (without checksum).
// Throws std::invalid_argument on format/checksum errors.
// out_type receives the detected encoding type.
std::vector<uint8_t> bech32_decode_raw(const std::string& bech,
                                        const std::string& expected_hrp,
                                        Bech32Type& out_type);

// Convert between bit groups (e.g. 8-bit bytes <-> 5-bit bech32 values).
// pad=true: left-pad remaining bits with zeros (for encode, 8->5).
// pad=false: reject non-zero remaining bits (for decode, 5->8).
// Throws std::invalid_argument on invalid data or padding.
std::vector<uint8_t> convert_bits(const std::vector<uint8_t>& data,
                                   int from_bits, int to_bits, bool pad);

// Overload accepting raw pointer + length.
std::vector<uint8_t> convert_bits(const uint8_t* data, size_t len,
                                   int from_bits, int to_bits, bool pad);

} // namespace internal
} // namespace nutcpp
