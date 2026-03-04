#include "nutcpp/encoding/token_v4_encoder.h"
#include "nutcpp/encoding/base64_url.h"
#include "nutcpp/encoding/convert_utils.h"
#include "nutcpp/types/proof.h"
#include "nutcpp/types/priv_key.h"
#include <nlohmann/json.hpp>
#include <map>
#include <set>
#include <stdexcept>

using namespace std;
using ordered_json = nlohmann::ordered_json;

namespace nutcpp::encoding {

string TokenV4Encoder::encode(const CashuToken& token) const {
    // V4 tokens require all proofs from the same mint
    set<string> mints;
    for (auto& t : token.tokens)
        mints.insert(t.mint);
    if (mints.size() != 1)
        throw invalid_argument("All proofs must have the same mint in V4 tokens");

    if (!token.unit.has_value())
        throw invalid_argument("V4 tokens require a unit");

    // Group proofs by keyset ID, preserving encounter order
    vector<string> keyset_order;
    map<string, vector<const Proof*>> groups;

    for (auto& t : token.tokens) {
        for (auto& proof : t.proofs) {
            string kid = proof.id.to_string();
            if (groups.find(kid) == groups.end())
                keyset_order.push_back(kid);
            groups[kid].push_back(&proof);
        }
    }

    // Build CBOR proof sets array
    auto proof_sets = ordered_json::array();
    for (auto& kid : keyset_order) {
        ordered_json proof_set;
        proof_set["i"] = ordered_json::binary(hex_to_bytes(kid));

        auto proofs_array = ordered_json::array();
        for (auto* proof : groups[kid]) {
            ordered_json p;
            p["a"] = proof->amount;
            p["s"] = proof->secret;
            p["c"] = ordered_json::binary(hex_to_bytes(proof->C.to_hex()));

            if (proof->dleq.has_value()) {
                auto& d = proof->dleq.value();
                ordered_json dleq;
                dleq["e"] = ordered_json::binary(hex_to_bytes(d.e.to_hex()));
                dleq["s"] = ordered_json::binary(hex_to_bytes(d.s.to_hex()));
                dleq["r"] = ordered_json::binary(hex_to_bytes(d.r.to_hex()));
                p["d"] = dleq;
            }

            if (proof->witness.has_value())
                p["w"] = proof->witness.value();

            if (proof->p2pk_e.has_value())
                p["pe"] = ordered_json::binary(hex_to_bytes(proof->p2pk_e.value().to_hex()));

            proofs_array.push_back(p);
        }
        proof_set["p"] = proofs_array;
        proof_sets.push_back(proof_set);
    }

    // Top-level CBOR map: key order matches DotNut (d optional first, t, m, u)
    ordered_json cbor;
    if (token.memo.has_value())
        cbor["d"] = token.memo.value();
    cbor["t"] = proof_sets;
    cbor["m"] = *mints.begin();
    cbor["u"] = token.unit.value();

    auto cbor_bytes = ordered_json::to_cbor(cbor);
    return Base64Url::encode(cbor_bytes.data(), cbor_bytes.size());
}

CashuToken TokenV4Encoder::decode(const string& payload) const {
    auto raw = Base64Url::decode(payload);
    auto cbor = ordered_json::from_cbor(raw);

    string mint = cbor.at("m").get<string>();
    string unit = cbor.at("u").get<string>();

    optional<string> memo;
    if (cbor.contains("d"))
        memo = cbor.at("d").get<string>();

    vector<Proof> proofs;
    for (auto& proof_set : cbor.at("t")) {
        auto& id_bin = proof_set.at("i").get_binary();
        KeysetId keyset_id(bytes_to_hex(id_bin.data(), id_bin.size()));

        for (auto& p : proof_set.at("p")) {
            uint64_t amount = p.at("a").get<uint64_t>();
            string secret = p.at("s").get<string>();

            auto& c_bin = p.at("c").get_binary();
            PubKey C(bytes_to_hex(c_bin.data(), c_bin.size()));

            optional<DLEQProof> dleq;
            if (p.contains("d")) {
                auto& d = p.at("d");
                auto& e_bin = d.at("e").get_binary();
                auto& s_bin = d.at("s").get_binary();
                auto& r_bin = d.at("r").get_binary();
                dleq = DLEQProof(
                    PrivKey(bytes_to_hex(e_bin.data(), e_bin.size())),
                    PrivKey(bytes_to_hex(s_bin.data(), s_bin.size())),
                    PrivKey(bytes_to_hex(r_bin.data(), r_bin.size()))
                );
            }

            optional<string> witness;
            if (p.contains("w"))
                witness = p.at("w").get<string>();

            optional<PubKey> p2pk_e;
            if (p.contains("pe")) {
                auto& pe_bin = p.at("pe").get_binary();
                p2pk_e = PubKey(bytes_to_hex(pe_bin.data(), pe_bin.size()));
            }

            proofs.emplace_back(amount, keyset_id, secret, C, witness, dleq, p2pk_e);
        }
    }

    return CashuToken(
        {Token(mint, proofs)},
        unit,
        memo
    );
}

} // namespace nutcpp::encoding
