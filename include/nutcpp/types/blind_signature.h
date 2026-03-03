#pragma once

#include <cstdint>
#include <optional>
#include <nlohmann/json.hpp>
#include "nutcpp/types/pub_key.h"
#include "nutcpp/types/keyset_id.h"
#include "nutcpp/types/dleq.h"

namespace nutcpp {

// BlindSignature (C_): mint's blind signature over B_
struct BlindSignature {
    uint64_t amount;
    KeysetId id;
    PubKey C_;
    std::optional<DLEQProof> dleq;

    BlindSignature(uint64_t amount, const KeysetId& id, const PubKey& C_,
                   std::optional<DLEQProof> dleq = std::nullopt)
        : amount(amount), id(id), C_(C_), dleq(dleq) {}
};

inline void to_json(nlohmann::json& j, const BlindSignature& bs) {
    j = {
        {"amount", bs.amount},
        {"id", bs.id},
        {"C_", bs.C_}
    };
    if (bs.dleq.has_value())
        j["dleq"] = bs.dleq.value();
}

inline void from_json(const nlohmann::json& j, BlindSignature& bs) {
    std::optional<DLEQProof> dleq;
    if (j.contains("dleq") && !j["dleq"].is_null()) {
        auto& d = j["dleq"];
        dleq = DLEQProof{
            PrivKey(d.at("e").get<std::string>()),
            PrivKey(d.at("s").get<std::string>()),
            PrivKey(d.at("r").get<std::string>())
        };
    }

    bs = BlindSignature(
        j.at("amount").get<uint64_t>(),
        KeysetId(j.at("id").get<std::string>()),
        PubKey(j.at("C_").get<std::string>()),
        dleq
    );
}

} // namespace nutcpp
