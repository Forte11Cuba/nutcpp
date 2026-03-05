#pragma once

// Internal BIP-32 key derivation for NUT-13 deterministic secrets.
// Supports hardened and non-hardened derivation using libsecp256k1.

#include <vector>
#include <string>
#include <cstdint>

namespace nutcpp {
namespace internal {

struct BIP32Key {
    unsigned char private_key[32];
    unsigned char chain_code[32];
};

// Derive master key from seed using HMAC-SHA512("Bitcoin seed", seed).
BIP32Key bip32_master_key(const uint8_t* seed, size_t seed_len);

// Derive key at BIP-32 path from seed.
// Path format: "m/129372'/0'/864559728'/0'/0"
// Hardened indices marked with '
BIP32Key bip32_derive_path(const std::string& path,
                           const uint8_t* seed, size_t seed_len);

} // namespace internal
} // namespace nutcpp
