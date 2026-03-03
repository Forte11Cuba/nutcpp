#pragma once

#include <map>
#include <string>
#include <optional>
#include <cstdint>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include "nutcpp/types/pub_key.h"
#include "nutcpp/types/keyset_id.h"

namespace nutcpp {

// Keyset: map of amount -> PubKey, with keyset ID derivation (NUT-02).
// Equivalent to DotNut Keyset.cs (Dictionary<ulong, PubKey>).
class Keyset : public std::map<uint64_t, PubKey> {
public:
    using std::map<uint64_t, PubKey>::map;

    // Derive keyset ID from public keys and metadata.
    // v0x00 (V1 deprecated): SHA256(concat pubkey bytes), first 14 hex chars + "00" prefix = 16 chars
    // v0x01 (V2 current):    SHA256("amount:pubkey,...|unit:X|..."), full hex + "01" prefix = 66 chars
    KeysetId get_keyset_id(
        uint8_t version = 0x00,
        const std::optional<std::string>& unit = std::nullopt,
        std::optional<uint64_t> input_fee_ppk = std::nullopt,
        const std::optional<std::string>& final_expiry = std::nullopt
    ) const;

    // Verify that a keyset ID matches this keyset's derived ID.
    // Extracts version from the keyset_id, derives, and compares (prefix match allowed).
    bool verify_keyset_id(
        const KeysetId& keyset_id,
        const std::optional<std::string>& unit = std::nullopt,
        std::optional<uint64_t> input_fee_ppk = std::nullopt,
        const std::optional<std::string>& final_expiry = std::nullopt
    ) const;
};

// JSON: {"1": "03a40f...", "2": "03fd4c..."} — amount as string key, pubkey hex as value.
inline void to_json(nlohmann::json& j, const Keyset& ks) {
    j = nlohmann::json::object();
    for (const auto& [amount, pubkey] : ks) {
        j[std::to_string(amount)] = pubkey.to_hex();
    }
}

inline void from_json(const nlohmann::json& j, Keyset& ks) {
    if (!j.is_object()) {
        throw std::runtime_error("Keyset JSON must be an object");
    }
    ks.clear();
    for (auto it = j.begin(); it != j.end(); ++it) {
        uint64_t amount;
        try {
            amount = std::stoull(it.key());
        } catch (...) {
            throw std::runtime_error("Invalid key amount in JSON: '" + it.key() + "'");
        }
        std::string hex = it.value().get<std::string>();
        if (hex.size() != 66) {
            throw std::runtime_error("Invalid public key (not compressed?): " + hex);
        }
        if (hex.substr(0, 2) != "02" && hex.substr(0, 2) != "03") {
            throw std::runtime_error("Invalid compressed pubkey prefix: " + hex);
        }
        ks.emplace(amount, PubKey{hex});
    }
}

} // namespace nutcpp
