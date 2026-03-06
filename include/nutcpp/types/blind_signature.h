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
    std::optional<DLEQ> dleq;

    BlindSignature(uint64_t amount, const KeysetId& id, const PubKey& C_,
                   std::optional<DLEQ> dleq = std::nullopt)
        : amount(amount), id(id), C_(C_), dleq(dleq) {}
};

} // namespace nutcpp

namespace nlohmann {
template <>
struct adl_serializer<nutcpp::BlindSignature> {
    static void to_json(json& j, const nutcpp::BlindSignature& bs) {
        j = {
            {"amount", bs.amount},
            {"id", bs.id},
            {"C_", bs.C_}
        };
        if (bs.dleq.has_value())
            j["dleq"] = bs.dleq.value();
    }
    static nutcpp::BlindSignature from_json(const json& j) {
        std::optional<nutcpp::DLEQ> dleq;
        if (j.contains("dleq") && !j["dleq"].is_null())
            dleq = j["dleq"].get<nutcpp::DLEQ>();

        return nutcpp::BlindSignature(
            j.at("amount").get<uint64_t>(),
            j.at("id").get<nutcpp::KeysetId>(),
            j.at("C_").get<nutcpp::PubKey>(),
            dleq
        );
    }
};
} // namespace nlohmann
