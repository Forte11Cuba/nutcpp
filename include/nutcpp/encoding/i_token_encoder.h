#pragma once

#include <string>
#include "nutcpp/types/cashu_token.h"

namespace nutcpp::encoding {

// Abstract interface for token encoders (V3 JSON, V4 CBOR).
// Encode/decode work on the payload only (without "cashu" prefix + version letter).
// The prefix handling is done by TokenHelper.
class ITokenEncoder {
public:
    virtual ~ITokenEncoder() = default;
    virtual std::string encode(const CashuToken& token) const = 0;
    virtual CashuToken decode(const std::string& token) const = 0;
};

} // namespace nutcpp::encoding
