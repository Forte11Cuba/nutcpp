#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <nlohmann/json.hpp>
#include "nutcpp/types/secret.h"

namespace nutcpp {

// NUT-10: Structured proof secret base.
// JSON: {"nonce":"...","data":"...","tags":[["key","val1"],["key2","val2"]]}
struct Nut10ProofSecret {
    std::string nonce;
    std::string data;
    std::optional<std::vector<std::vector<std::string>>> tags;

    Nut10ProofSecret() = default;

    virtual ~Nut10ProofSecret() = default;

    bool operator==(const Nut10ProofSecret& other) const;
    bool operator!=(const Nut10ProofSecret& other) const { return !(*this == other); }

    // Find first tag with given key, returns nullptr if not found
    const std::vector<std::string>* find_tag(const std::string& key) const;
};

inline void to_json(nlohmann::json& j, const Nut10ProofSecret& ps) {
    j["nonce"] = ps.nonce;
    if (!ps.data.empty())
        j["data"] = ps.data;
    if (ps.tags.has_value())
        j["tags"] = ps.tags.value();
}

inline void from_json(const nlohmann::json& j, Nut10ProofSecret& ps) {
    ps.nonce = j.at("nonce").get<std::string>();
    if (j.contains("data") && !j["data"].is_null())
        ps.data = j["data"].get<std::string>();
    else
        ps.data.clear();
    if (j.contains("tags") && !j["tags"].is_null())
        ps.tags = j["tags"].get<std::vector<std::vector<std::string>>>();
    else
        ps.tags = std::nullopt;
}

// NUT-10: Wrapper that pairs a key ("P2PK" or "HTLC") with a proof secret.
// JSON: serialized as array ["key", {proof_secret}]
// Implements ISecret: get_bytes() serializes to JSON UTF-8, to_curve() hashes to point.
class Nut10Secret : public ISecret {
public:
    Nut10Secret(const std::string& key, std::shared_ptr<Nut10ProofSecret> proof_secret);
    Nut10Secret(const std::string& key, std::shared_ptr<Nut10ProofSecret> proof_secret,
                const std::string& original_string);

    const std::string& key() const { return key_; }
    const std::shared_ptr<Nut10ProofSecret>& proof_secret() const { return proof_secret_; }

    // ISecret interface
    std::vector<unsigned char> get_bytes() const override;
    PubKey to_curve() const override;

    // Serialize to JSON string (canonical form)
    std::string to_json_string() const;

private:
    std::string key_;
    std::shared_ptr<Nut10ProofSecret> proof_secret_;
    std::string original_string_;  // preserved for exact byte reproduction
};

// Dispatch: parse a proof secret string into the appropriate ISecret subclass.
// - If JSON array starting with "P2PK" or "HTLC": creates Nut10Secret
// - Otherwise: creates StringSecret
std::unique_ptr<ISecret> parse_secret(const std::string& s);

} // namespace nutcpp
