#pragma once

#include <string>
#include <array>
#include <stdexcept>
#include <secp256k1.h>
#include <nlohmann/json.hpp>

namespace nutcpp {

class PubKey {
public:
    // Construct from hex string (66 chars = 33 bytes compressed)
    explicit PubKey(const std::string& hex);

    // Construct from raw secp256k1_pubkey
    PubKey(const secp256k1_pubkey& key);

    // Export as lowercase hex string (compressed, 66 chars)
    std::string to_hex() const;

    // Access the underlying secp256k1_pubkey
    const secp256k1_pubkey& get() const { return key_; }

    // Comparison
    bool operator==(const PubKey& other) const;
    bool operator!=(const PubKey& other) const { return !(*this == other); }

private:
    secp256k1_pubkey key_;
};

// JSON: serializes as hex string
void to_json(nlohmann::json& j, const PubKey& pk);
void from_json(const nlohmann::json& j, PubKey& pk);

} // namespace nutcpp
