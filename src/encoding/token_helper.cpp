#include "nutcpp/encoding/token_helper.h"
#include "nutcpp/encoding/token_v3_encoder.h"
#include "nutcpp/encoding/token_v4_encoder.h"
#include <stdexcept>
#include <algorithm>

using namespace std;

namespace nutcpp::encoding {

static const string CASHU_PREFIX = "cashu";
static const string CASHU_URI_SCHEME = "cashu:";

// Shorten v1 keyset IDs to 16 hex chars (8 bytes) for compact encoding
static KeysetId maybe_shorten_id(const KeysetId& id) {
    if (id.get_version() != 0x01) return id;
    auto s = id.to_string();
    if (s.length() <= 16) return id;
    return KeysetId(s.substr(0, 16));
}

// Resolve short keyset IDs back to full IDs using a known list
static vector<Proof> map_short_keyset_ids(const vector<Proof>& proofs,
                                          const vector<KeysetId>& keyset_ids) {
    // Check if any proof needs mapping
    bool needs_mapping = false;
    for (auto& p : proofs) {
        if (p.id.get_version() == 0x01 && p.id.to_string().length() == 16) {
            needs_mapping = true;
            break;
        }
    }
    if (!needs_mapping) return proofs;

    if (keyset_ids.empty())
        throw invalid_argument(
            "Encountered short keyset IDs but no keysets were provided for mapping");

    vector<Proof> result;
    result.reserve(proofs.size());

    for (auto& proof : proofs) {
        if (proof.id.get_version() != 0x01 || proof.id.to_string().length() != 16) {
            result.push_back(proof);
            continue;
        }

        // Find matching full keyset ID that starts with the short ID
        auto short_id = proof.id.to_string();
        const KeysetId* match = nullptr;
        for (auto& kid : keyset_ids) {
            auto full_id = kid.to_string();
            if (full_id.length() >= 16 && full_id.substr(0, 16) == short_id) {
                match = &kid;
                break;
            }
        }

        if (!match)
            throw runtime_error(
                "Couldn't map short keyset ID " + short_id + " to any known keyset");

        result.emplace_back(proof.amount, *match, proof.secret, proof.C,
                            proof.witness, proof.dleq, proof.p2pk_e);
    }
    return result;
}

string TokenHelper::encode(const CashuToken& token,
                           const string& version,
                           bool make_uri) {
    // Prepare a copy with trimmed mint URLs and shortened keyset IDs
    vector<Token> prepared_tokens;
    prepared_tokens.reserve(token.tokens.size());

    for (auto& t : token.tokens) {
        // Trim trailing slashes from mint URL
        string mint = t.mint;
        while (!mint.empty() && mint.back() == '/')
            mint.pop_back();

        // Shorten keyset IDs
        vector<Proof> proofs;
        proofs.reserve(t.proofs.size());
        for (auto& p : t.proofs) {
            proofs.emplace_back(p.amount, maybe_shorten_id(p.id), p.secret, p.C,
                                p.witness, p.dleq, p.p2pk_e);
        }
        prepared_tokens.emplace_back(mint, proofs);
    }

    CashuToken prepared(prepared_tokens, token.unit, token.memo);

    // Dispatch to the right encoder
    string payload;
    if (version == "A") {
        TokenV3Encoder encoder;
        payload = encoder.encode(prepared);
    } else if (version == "B") {
        TokenV4Encoder encoder;
        payload = encoder.encode(prepared);
    } else {
        throw invalid_argument("Unsupported token version: " + version);
    }

    string result = CASHU_PREFIX + version + payload;
    if (make_uri)
        return CASHU_URI_SCHEME + result;
    return result;
}

CashuToken TokenHelper::decode(const string& token,
                                string& version,
                                const vector<KeysetId>& keyset_ids) {
    string input = token;

    // Strip URI scheme if present
    if (input.substr(0, CASHU_URI_SCHEME.length()) == CASHU_URI_SCHEME)
        input = input.substr(CASHU_URI_SCHEME.length());

    // Validate prefix
    if (input.substr(0, CASHU_PREFIX.length()) != CASHU_PREFIX)
        throw invalid_argument("Invalid cashu token");

    input = input.substr(CASHU_PREFIX.length());
    version = input.substr(0, 1);
    string payload = input.substr(1);

    // Dispatch to the right encoder
    auto decode_payload = [&]() -> CashuToken {
        if (version == "A") {
            TokenV3Encoder encoder;
            return encoder.decode(payload);
        } else if (version == "B") {
            TokenV4Encoder encoder;
            return encoder.decode(payload);
        }
        throw invalid_argument("Unsupported token version: " + version);
    };
    CashuToken decoded = decode_payload();

    // Resolve short keyset IDs if list provided
    if (!keyset_ids.empty()) {
        for (auto& t : decoded.tokens) {
            t.proofs = map_short_keyset_ids(t.proofs, keyset_ids);
        }
    }

    return decoded;
}

} // namespace nutcpp::encoding
