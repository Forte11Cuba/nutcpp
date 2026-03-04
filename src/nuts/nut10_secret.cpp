#include "nutcpp/nuts/nut10_secret.h"
#include "nutcpp/nuts/p2pk.h"
#include "nutcpp/crypto/cashu.h"

#include <nlohmann/json.hpp>
#include <stdexcept>

using namespace std;

namespace nutcpp {

// ============================================================
// Nut10ProofSecret
// ============================================================

bool Nut10ProofSecret::operator==(const Nut10ProofSecret& other) const {
    if (nonce != other.nonce || data != other.data)
        return false;

    // Both null → equal; one null → not equal
    if (!tags.has_value() && !other.tags.has_value())
        return true;
    if (!tags.has_value() || !other.tags.has_value())
        return false;

    const auto& a = tags.value();
    const auto& b = other.tags.value();
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

const vector<string>* Nut10ProofSecret::find_tag(const string& key) const {
    if (!tags.has_value())
        return nullptr;
    for (const auto& tag : tags.value()) {
        if (tag.size() >= 2 && tag[0] == key)
            return &tag;
    }
    return nullptr;
}

// ============================================================
// Nut10Secret
// ============================================================

Nut10Secret::Nut10Secret(const string& key, shared_ptr<Nut10ProofSecret> proof_secret)
    : key_(key), proof_secret_(move(proof_secret)) {
    if (!proof_secret_)
        throw invalid_argument("Nut10Secret: proof_secret must not be null");
}

Nut10Secret::Nut10Secret(const string& key, shared_ptr<Nut10ProofSecret> proof_secret,
                         const string& original_string)
    : key_(key), proof_secret_(move(proof_secret)), original_string_(original_string) {
    if (!proof_secret_)
        throw invalid_argument("Nut10Secret: proof_secret must not be null");
}

string Nut10Secret::to_json_string() const {
    // Serialize as JSON array: ["key", {proof_secret}]
    nlohmann::json ps_json;
    to_json(ps_json, *proof_secret_);
    nlohmann::json arr = nlohmann::json::array({key_, ps_json});
    return arr.dump();
}

vector<unsigned char> Nut10Secret::get_bytes() const {
    // If we have the original string, use it for exact byte reproduction
    if (!original_string_.empty()) {
        return vector<unsigned char>(original_string_.begin(), original_string_.end());
    }
    // Otherwise serialize to JSON
    string s = to_json_string();
    return vector<unsigned char>(s.begin(), s.end());
}

PubKey Nut10Secret::to_curve() const {
    auto bytes = get_bytes();
    return crypto::hash_to_curve(bytes);
}

// ============================================================
// parse_secret
// ============================================================

unique_ptr<ISecret> parse_secret(const string& s) {
    if (s.empty())
        return make_unique<StringSecret>(s); // StringSecret will throw on empty

    // Try to parse as JSON array ["P2PK", {...}] or ["HTLC", {...}]
    if (s.front() == '[') {
        nlohmann::json j;
        try {
            j = nlohmann::json::parse(s);
        } catch (const nlohmann::json::parse_error&) {
            // Not valid JSON, fall through to StringSecret
            return make_unique<StringSecret>(s);
        }

        if (j.is_array() && j.size() == 2 && j[0].is_string()) {
            string key = j[0].get<string>();
            if (key == "P2PK") {
                auto ps = make_shared<P2PKProofSecret>();
                from_json(j[1], *ps);
                return make_unique<Nut10Secret>(key, ps, s);
            }
            if (key == "HTLC") {
                // TODO: dispatch to HTLCProofSecret in PR 3
                auto ps = make_shared<Nut10ProofSecret>();
                from_json(j[1], *ps);
                return make_unique<Nut10Secret>(key, ps, s);
            }
        }
    }

    return make_unique<StringSecret>(s);
}

} // namespace nutcpp
