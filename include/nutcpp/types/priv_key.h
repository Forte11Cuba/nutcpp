#pragma once

#include <string>
#include <stdexcept>
#include <secp256k1.h>
#include <nlohmann/json.hpp>
#include "nutcpp/types/pub_key.h"

namespace nutcpp {

class PrivKey {
public:
    ~PrivKey();

    // Construct from hex string (64 chars = 32 bytes)
    explicit PrivKey(const std::string& hex);

    // Construct from raw 32 bytes
    PrivKey(const unsigned char key[32]);

    // Export as lowercase hex string (64 chars)
    std::string to_hex() const;

    // Derive the corresponding public key
    PubKey get_pub_key() const;

    // Access raw 32 bytes
    const unsigned char* data() const { return key_; }

private:
    unsigned char key_[32];
};

// JSON: serializes as hex string
void to_json(nlohmann::json& j, const PrivKey& sk);
void from_json(const nlohmann::json& j, PrivKey& sk);

} // namespace nutcpp
