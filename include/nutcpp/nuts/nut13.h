#pragma once

// NUT-13: Deterministic secret derivation from BIP-39 mnemonic.
// v0 (keyset 0x00): BIP-32 path derivation
// v1 (keyset 0x01): HMAC-SHA256 KDF

#include "nutcpp/types/keyset_id.h"

#include <vector>
#include <string>
#include <cstdint>

namespace nutcpp {

// Derive a deterministic secret for a given keyset and counter.
// Returns the secret as a lowercase hex string (like DotNut StringSecret).
std::string derive_secret(const std::vector<uint8_t>& seed,
                          const KeysetId& keyset_id,
                          uint32_t counter);

// Derive a deterministic blinding factor for a given keyset and counter.
// Returns 32 raw bytes suitable for use as a BIP-340 scalar.
std::vector<uint8_t> derive_blinding_factor(const std::vector<uint8_t>& seed,
                                            const KeysetId& keyset_id,
                                            uint32_t counter);

// Convert keyset ID hex to integer: big-endian interpretation mod (2^31 - 1).
// Used for BIP-32 derivation path (v0 keysets).
uint32_t get_keyset_id_int(const KeysetId& keyset_id);

// Build the NUT-13 BIP-32 derivation path string.
// secret_or_r: true = secret (leaf 0), false = blinding factor (leaf 1).
std::string get_derivation_path(const KeysetId& keyset_id,
                                uint32_t counter,
                                bool secret_or_r);

} // namespace nutcpp
