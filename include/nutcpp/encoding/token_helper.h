#pragma once

#include <string>
#include <vector>
#include <optional>
#include "nutcpp/types/cashu_token.h"
#include "nutcpp/types/keyset_id.h"

namespace nutcpp::encoding {

// Dispatcher for token encoding/decoding.
// Adds/strips "cashu" prefix + version letter (A=V3, B=V4).
// Handles URI scheme "cashu:" and short keyset ID mapping.
class TokenHelper {
public:
    // Encode a CashuToken to string: "cashu{A|B}{payload}"
    // version: "A" (V3 JSON) or "B" (V4 CBOR, default)
    // make_uri: if true, prepend "cashu:" URI scheme
    static std::string encode(const CashuToken& token,
                              const std::string& version = "B",
                              bool make_uri = false);

    // Decode a token string. Returns the CashuToken and the version letter.
    // Strips "cashu:" URI prefix if present.
    // keyset_ids: optional list to resolve short keyset IDs to full IDs.
    static CashuToken decode(const std::string& token,
                             std::string& version,
                             const std::vector<KeysetId>& keyset_ids = {});
};

} // namespace nutcpp::encoding
