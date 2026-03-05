#pragma once

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "nutcpp/types/proof.h"

namespace nutcpp::payment {

// NUT-18: Payload sent to the receiver via the transport.
// JSON keys use full names: "id", "memo", "mint", "unit", "proofs"
struct PaymentRequestPayload {
    std::optional<std::string> id;
    std::optional<std::string> memo;
    std::string mint;
    std::string unit;
    std::vector<Proof> proofs;

    PaymentRequestPayload() = default;

    PaymentRequestPayload(std::string mint, std::string unit,
                          std::vector<Proof> proofs,
                          std::optional<std::string> id = std::nullopt,
                          std::optional<std::string> memo = std::nullopt)
        : id(std::move(id)), memo(std::move(memo)),
          mint(std::move(mint)), unit(std::move(unit)),
          proofs(std::move(proofs)) {}
};

inline void to_json(nlohmann::json& j, const PaymentRequestPayload& p) {
    if (p.id.has_value())
        j["id"] = p.id.value();
    if (p.memo.has_value())
        j["memo"] = p.memo.value();
    j["mint"] = p.mint;
    j["unit"] = p.unit;
    j["proofs"] = p.proofs;
}

inline void from_json(const nlohmann::json& j, PaymentRequestPayload& p) {
    if (j.contains("id") && !j["id"].is_null())
        p.id = j["id"].get<std::string>();
    else
        p.id = std::nullopt;

    if (j.contains("memo") && !j["memo"].is_null())
        p.memo = j["memo"].get<std::string>();
    else
        p.memo = std::nullopt;

    p.mint = j.at("mint").get<std::string>();
    p.unit = j.at("unit").get<std::string>();
    p.proofs = j.at("proofs").get<std::vector<Proof>>();
}

} // namespace nutcpp::payment
