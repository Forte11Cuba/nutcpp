#pragma once

#include <string>
#include <vector>
#include <memory>
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

// JSON: StringSecret serializes as plain string.
// Nut10Secret dispatch will be added in Fase 5.
void to_json(nlohmann::json& j, const StringSecret& s);
void from_json(const nlohmann::json& j, StringSecret& s);

} // namespace nutcpp
