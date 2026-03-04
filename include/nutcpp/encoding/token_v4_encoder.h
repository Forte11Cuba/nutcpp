#pragma once

#include <string>
#include "nutcpp/encoding/i_token_encoder.h"

namespace nutcpp::encoding {

// V4 token encoder: CashuToken -> CBOR -> base64url (prefix "cashuB")
// Uses nlohmann::ordered_json for CBOR with deterministic key order.
// Handles the payload only; prefix is managed by TokenHelper.
class TokenV4Encoder : public ITokenEncoder {
public:
    std::string encode(const CashuToken& token) const override;
    CashuToken decode(const std::string& payload) const override;
};

} // namespace nutcpp::encoding
