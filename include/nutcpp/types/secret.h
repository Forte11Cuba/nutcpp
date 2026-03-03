#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include "nutcpp/types/pub_key.h"

namespace nutcpp {

// Abstract base for secrets (StringSecret, Nut10Secret)
class ISecret {
public:
    virtual ~ISecret() = default;

    // Raw bytes of the secret
    virtual std::vector<unsigned char> get_bytes() const = 0;

    // Hash secret to a point on secp256k1 (requires crypto/cashu.h)
    virtual PubKey to_curve() const = 0;
};

// Simple string-based secret (random or user-provided)
class StringSecret : public ISecret {
public:
    explicit StringSecret(const std::string& secret);

    const std::string& value() const { return secret_; }

    std::vector<unsigned char> get_bytes() const override;
    PubKey to_curve() const override;

private:
    std::string secret_;
};

} // namespace nutcpp

namespace nlohmann {
template <>
struct adl_serializer<nutcpp::StringSecret> {
    static void to_json(json& j, const nutcpp::StringSecret& s) { j = s.value(); }
    static nutcpp::StringSecret from_json(const json& j) { return nutcpp::StringSecret(j.get<std::string>()); }
};
} // namespace nlohmann
