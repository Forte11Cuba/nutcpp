#pragma once

// Internal NIP-19 helpers for NUT-26 payment requests.
// Handles npub and nprofile bech32-encoded Nostr entities.
// npub/nprofile use Bech32 (not Bech32m). TLV uses 1-byte tag + 1-byte length.

#include <vector>
#include <string>
#include <cstdint>

namespace nutcpp {
namespace internal {

struct NprofileData {
    std::vector<uint8_t> pubkey;      // 32-byte x-only public key
    std::vector<std::string> relays;  // relay URLs (may be empty)
};

// Decode npub or nprofile string. Dispatches by prefix.
// Returns 32-byte pubkey + relay list (empty for npub).
// Throws std::invalid_argument on format errors.
NprofileData decode_nostr(const std::string& str);

// Decode npub bech32 string to 32-byte pubkey.
// Throws std::invalid_argument if not valid Bech32 or wrong length.
std::vector<uint8_t> decode_npub(const std::string& npub);

// Decode nprofile bech32 string to pubkey + relays.
// Throws std::invalid_argument on format errors.
NprofileData decode_nprofile(const std::string& nprofile);

// Encode pubkey (32 bytes) + relays to nprofile bech32 string.
// Always produces nprofile format (even with 0 relays), matching DotNut behavior.
std::string encode_nprofile(const uint8_t* pubkey, size_t pubkey_len,
                             const std::vector<std::string>& relays);

// Convenience overload.
std::string encode_nprofile(const std::vector<uint8_t>& pubkey,
                             const std::vector<std::string>& relays);

} // namespace internal
} // namespace nutcpp
