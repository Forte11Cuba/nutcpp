#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <nlohmann/json.hpp>
#include "nutcpp/nuts/nut10_secret.h"
#include "nutcpp/types/priv_key.h"

namespace nutcpp {

// ============================================================
// NUT-11: P2PK Witness
// ============================================================

struct P2PKWitness {
    std::vector<std::string> signatures;

    P2PKWitness() = default;
    virtual ~P2PKWitness() = default;
};

inline void to_json(nlohmann::json& j, const P2PKWitness& w) {
    j["signatures"] = w.signatures;
}

inline void from_json(const nlohmann::json& j, P2PKWitness& w) {
    if (j.contains("signatures") && !j["signatures"].is_null())
        w.signatures = j["signatures"].get<std::vector<std::string>>();
    else
        w.signatures.clear();
}

class P2PKProofSecret;  // forward declaration for P2PKBuilder::build()

// ============================================================
// NUT-11: P2PK Builder
// ============================================================

class P2PKBuilder {
public:
    std::vector<PubKey> pubkeys;
    std::optional<int64_t> lock;  // unix timestamp
    std::vector<PubKey> refund_pubkeys;
    int signature_threshold = 1;
    std::string sig_flag;
    std::string nonce;
    std::optional<int> refund_signature_threshold;

    // Build a P2PKProofSecret from current parameters
    P2PKProofSecret build() const;

    // Load parameters from an existing Nut10ProofSecret
    static P2PKBuilder load(const Nut10ProofSecret& ps);

    // Validate builder parameters
    void validate() const;
};

// ============================================================
// NUT-11: P2PK Proof Secret
// ============================================================

class P2PKProofSecret : public Nut10ProofSecret {
public:
    static constexpr const char* KEY = "P2PK";

    P2PKProofSecret() = default;

    // Get allowed pubkeys for spending (normal path). Always available.
    std::vector<PubKey> get_allowed_pubkeys(int& required_sigs) const;

    // Get allowed pubkeys for refund path.
    // Returns empty + nullopt if locktime not expired.
    // Returns empty + 0 if locktime expired and no refund keys (freely spendable).
    std::vector<PubKey> get_allowed_refund_pubkeys(std::optional<int>& required_sigs) const;

    // Generate witness: SHA256(msg) then sign with matching private keys
    std::optional<P2PKWitness> generate_witness(
        const std::vector<unsigned char>& msg, const std::vector<PrivKey>& keys) const;

    // Verify witness against secret bytes
    virtual bool verify_witness(const ISecret& secret, const P2PKWitness& witness) const;
    virtual bool verify_witness(const std::vector<unsigned char>& message, const P2PKWitness& witness) const;

    // Verify witness against pre-hashed 32-byte message
    virtual bool verify_witness_hash(const unsigned char hash[32], const P2PKWitness& witness) const;

protected:
    // Try to sign with a set of allowed keys
    std::pair<bool, P2PKWitness> try_sign_path(
        const std::vector<PubKey>& allowed_keys, int required_sigs,
        const std::vector<PrivKey>& available_keys, const unsigned char msg[32]) const;

    // Verify signatures against a set of allowed keys
    bool verify_path(
        const std::vector<PubKey>& allowed_keys, int required_sigs,
        const std::vector<std::string>& sig_hexes, const unsigned char hash[32]) const;
};

} // namespace nutcpp
