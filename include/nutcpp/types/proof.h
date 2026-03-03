#pragma once

#include <cstdint>
#include <string>
#include <optional>
#include <nlohmann/json.hpp>
#include "nutcpp/types/pub_key.h"
#include "nutcpp/types/keyset_id.h"
#include "nutcpp/types/dleq.h"

namespace nutcpp {

// Proof: a Cashu coin — proves ownership of ecash.
// The secret is stored as string for now. When Nut10Secret exists (Phase 5),
// this will use ISecret dispatch for structured secrets.
struct Proof {
    uint64_t amount;
    KeysetId id;
    std::string secret;
    PubKey C;
    std::optional<std::string> witness;
    std::optional<DLEQProof> dleq;
    std::optional<PubKey> p2pk_e;  // NUT-28 P2BK: ephemeral pubkey E, not sent to mint

    Proof(uint64_t amount, const KeysetId& id, const std::string& secret,
          const PubKey& C,
          std::optional<std::string> witness = std::nullopt,
          std::optional<DLEQProof> dleq = std::nullopt,
          std::optional<PubKey> p2pk_e = std::nullopt)
        : amount(amount), id(id), secret(secret), C(C),
          witness(witness), dleq(dleq), p2pk_e(p2pk_e) {}
};

inline void to_json(nlohmann::json& j, const Proof& p) {
    j = {
        {"amount", p.amount},
        {"id", p.id},
        {"secret", p.secret},
        {"C", p.C}
    };
    if (p.witness.has_value())
        j["witness"] = p.witness.value();
    if (p.dleq.has_value())
        j["dleq"] = p.dleq.value();
    // p2pk_e is wallet-internal, never serialized to mint
}

inline void from_json(const nlohmann::json& j, Proof& p) {
    std::optional<std::string> witness;
    if (j.contains("witness") && !j["witness"].is_null())
        witness = j["witness"].get<std::string>();

    std::optional<DLEQProof> dleq;
    if (j.contains("dleq") && !j["dleq"].is_null()) {
        auto& d = j["dleq"];
        dleq = DLEQProof{
            PrivKey(d.at("e").get<std::string>()),
            PrivKey(d.at("s").get<std::string>()),
            PrivKey(d.at("r").get<std::string>())
        };
    }

    p = Proof(
        j.at("amount").get<uint64_t>(),
        KeysetId(j.at("id").get<std::string>()),
        j.at("secret").get<std::string>(),
        PubKey(j.at("C").get<std::string>()),
        witness,
        dleq
    );
}

} // namespace nutcpp
