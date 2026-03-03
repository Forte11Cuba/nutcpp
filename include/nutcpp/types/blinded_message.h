#pragma once

#include <cstdint>
#include <string>
#include <optional>
#include <nlohmann/json.hpp>
#include "nutcpp/types/pub_key.h"
#include "nutcpp/types/keyset_id.h"

namespace nutcpp {

// BlindedMessage (B_): sent by wallet to mint for signing
struct BlindedMessage {
    uint64_t amount;
    KeysetId id;
    PubKey B_;
    std::optional<std::string> witness;

    BlindedMessage(uint64_t amount, const KeysetId& id, const PubKey& B_,
                   std::optional<std::string> witness = std::nullopt)
        : amount(amount), id(id), B_(B_), witness(witness) {}
};

inline void to_json(nlohmann::json& j, const BlindedMessage& bm) {
    j = {
        {"amount", bm.amount},
        {"id", bm.id},
        {"B_", bm.B_}
    };
    if (bm.witness.has_value())
        j["witness"] = bm.witness.value();
}

inline void from_json(const nlohmann::json& j, BlindedMessage& bm) {
    std::optional<std::string> witness;
    if (j.contains("witness") && !j["witness"].is_null())
        witness = j["witness"].get<std::string>();

    bm = BlindedMessage(
        j.at("amount").get<uint64_t>(),
        KeysetId(j.at("id").get<std::string>()),
        PubKey(j.at("B_").get<std::string>()),
        witness
    );
}

} // namespace nutcpp
