#pragma once

// Internal BIP-39 implementation for NUT-13 deterministic secrets.
// Only supports English wordlist. Passphrase is optional (default empty).

#include <vector>
#include <string>
#include <cstdint>

namespace nutcpp {
namespace internal {

// Derives a 64-byte seed from a BIP-39 mnemonic phrase.
// Uses PBKDF2-HMAC-SHA512 with salt = "mnemonic" + passphrase, 2048 iterations.
// Throws std::invalid_argument if mnemonic is empty or has invalid word count.
std::vector<uint8_t> mnemonic_to_seed(const std::string& mnemonic,
                                       const std::string& passphrase = "");

} // namespace internal
} // namespace nutcpp
