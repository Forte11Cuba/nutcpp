#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include "nutcpp/encoding/i_token_encoder.h"
#include "nutcpp/encoding/base64_url.h"

namespace nutcpp::encoding {

// V3 token encoder: CashuToken -> JSON -> base64url (prefix "cashuA")
// Uses ordered_json to match spec key order: {token, unit?, memo?}
// Handles the payload only; prefix is managed by TokenHelper.
class TokenV3Encoder : public ITokenEncoder {
public:
    std::string encode(const CashuToken& token) const override {
        using oj = nlohmann::ordered_json;

        // Build JSON with spec-defined key order
        auto tokens_arr = oj::array();
        for (auto& t : token.tokens) {
            oj tj;
            tj["mint"] = t.mint;

            auto proofs_arr = oj::array();
            for (auto& p : t.proofs) {
                oj pj;
                pj["amount"] = p.amount;
                pj["id"] = p.id.to_string();
                pj["secret"] = p.secret;
                pj["C"] = p.C.to_hex();
                if (p.witness.has_value())
                    pj["witness"] = p.witness.value();
                if (p.dleq.has_value()) {
                    oj dj;
                    dj["e"] = p.dleq->e.to_hex();
                    dj["s"] = p.dleq->s.to_hex();
                    dj["r"] = p.dleq->r.to_hex();
                    pj["dleq"] = dj;
                }
                proofs_arr.push_back(pj);
            }
            tj["proofs"] = proofs_arr;
            tokens_arr.push_back(tj);
        }

        oj j;
        j["token"] = tokens_arr;
        if (token.unit.has_value())
            j["unit"] = token.unit.value();
        if (token.memo.has_value())
            j["memo"] = token.memo.value();

        return Base64Url::encode(j.dump());
    }

    CashuToken decode(const std::string& payload) const override {
        std::string json_str = Base64Url::decode_to_string(payload);
        return nlohmann::json::parse(json_str).get<CashuToken>();
    }
};

} // namespace nutcpp::encoding
