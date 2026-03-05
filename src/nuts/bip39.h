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
// Validates word count, each word against BIP-39 English, and checksum.
// Throws std::invalid_argument if mnemonic is invalid.
std::vector<uint8_t> mnemonic_to_seed(const std::string& mnemonic,
                                       const std::string& passphrase = "");

// Validates the BIP-39 checksum embedded in the mnemonic.
// Returns true if the last CS bits match SHA-256(entropy).
// Returns false if words are invalid or checksum doesn't match.
bool validate_mnemonic_checksum(const std::string& mnemonic);

} // namespace internal
} // namespace nutcpp
