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

} // namespace nutcpp

namespace nlohmann {
template <>
struct adl_serializer<nutcpp::PrivKey> {
    static void to_json(json& j, const nutcpp::PrivKey& sk) { j = sk.to_hex(); }
    static nutcpp::PrivKey from_json(const json& j) { return nutcpp::PrivKey(j.get<std::string>()); }
};
} // namespace nlohmann
