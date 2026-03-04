#pragma once

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "nutcpp/nuts/p2pk.h"

namespace nutcpp {

// ============================================================
// NUT-14: HTLC Witness
// ============================================================

struct HTLCWitness : public P2PKWitness {
    std::optional<std::string> preimage;  // hex, nullable post-locktime

    HTLCWitness() = default;
    ~HTLCWitness() override = default;
};

inline void to_json(nlohmann::json& j, const HTLCWitness& w) {
    if (w.preimage.has_value())
        j["preimage"] = w.preimage.value();
    j["signatures"] = w.signatures;
}

inline void from_json(const nlohmann::json& j, HTLCWitness& w) {
    if (j.contains("preimage") && !j["preimage"].is_null())
        w.preimage = j["preimage"].get<std::string>();
    else
        w.preimage = std::nullopt;

    if (j.contains("signatures") && !j["signatures"].is_null())
        w.signatures = j["signatures"].get<std::vector<std::string>>();
    else
        w.signatures.clear();
}

// ============================================================
// NUT-14: HTLC Builder
// ============================================================

class HTLCProofSecret;  // forward declaration

class HTLCBuilder : public P2PKBuilder {
public:
    std::string hashlock;  // SHA256 hash, 64 hex chars

    // Build an HTLCProofSecret from current parameters
    HTLCProofSecret build() const;

    // Load parameters from an existing Nut10ProofSecret
    static HTLCBuilder load(const Nut10ProofSecret& ps);
};

// ============================================================
// NUT-14: HTLC Proof Secret
// ============================================================

class HTLCProofSecret : public P2PKProofSecret {
public:
    static constexpr const char* KEY = "HTLC";

    HTLCProofSecret() = default;

    // Override: use HTLCBuilder to parse pubkeys (data is hashlock, not pubkey)
    std::vector<PubKey> get_allowed_pubkeys(int& required_sigs) const;
    std::vector<PubKey> get_allowed_refund_pubkeys(std::optional<int>& required_sigs) const;

    // Verify that SHA256(preimage) == hashlock (data field)
    bool verify_preimage(const std::string& preimage_hex) const;

    // Generate HTLC witness: preimage + signatures
    std::optional<HTLCWitness> generate_witness(
        const std::vector<unsigned char>& msg, const std::vector<PrivKey>& keys,
        const std::string& preimage_hex) const;

    // Override: verify preimage BEFORE verifying signatures
    bool verify_witness_hash(const unsigned char hash[32], const P2PKWitness& witness) const override;
};

} // namespace nutcpp
