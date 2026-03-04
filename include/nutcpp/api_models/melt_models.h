#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <nlohmann/json.hpp>
#include "nutcpp/types/proof.h"
#include "nutcpp/types/blinded_message.h"
#include "nutcpp/types/blind_signature.h"

namespace nutcpp::api {

// NUT-05/NUT-23: POST /v1/melt/quote/bolt11 request.
struct PostMeltQuoteBolt11Request {
    std::string request;
    std::string unit;

    PostMeltQuoteBolt11Request() = default;
    PostMeltQuoteBolt11Request(std::string request, std::string unit)
        : request(std::move(request)), unit(std::move(unit)) {}
};

inline void to_json(nlohmann::json& j, const PostMeltQuoteBolt11Request& r) {
    j = {{"request", r.request}, {"unit", r.unit}};
}

inline void from_json(const nlohmann::json& j, PostMeltQuoteBolt11Request& r) {
    r.request = j.at("request").get<std::string>();
    r.unit = j.at("unit").get<std::string>();
}

// NUT-05/NUT-23: melt quote response (also used as POST /v1/melt/bolt11 response).
struct PostMeltQuoteBolt11Response {
    std::string quote;
    uint64_t amount = 0;
    uint64_t fee_reserve = 0;
    std::string state;
    std::optional<uint64_t> expiry;
    std::optional<std::string> payment_preimage;
    std::optional<std::vector<BlindSignature>> change;    // NUT-08 overpaid fee change

    PostMeltQuoteBolt11Response() = default;
};

inline void to_json(nlohmann::json& j, const PostMeltQuoteBolt11Response& r) {
    j = {
        {"quote", r.quote},
        {"amount", r.amount},
        {"fee_reserve", r.fee_reserve},
        {"state", r.state}
    };
    if (r.expiry.has_value())
        j["expiry"] = r.expiry.value();
    if (r.payment_preimage.has_value())
        j["payment_preimage"] = r.payment_preimage.value();
    if (r.change.has_value())
        j["change"] = r.change.value();
}

inline void from_json(const nlohmann::json& j, PostMeltQuoteBolt11Response& r) {
    r.quote = j.at("quote").get<std::string>();
    r.amount = j.at("amount").get<uint64_t>();
    r.fee_reserve = j.at("fee_reserve").get<uint64_t>();
    r.state = j.at("state").get<std::string>();
    if (j.contains("expiry") && !j["expiry"].is_null())
        r.expiry = j["expiry"].get<uint64_t>();
    else
        r.expiry = std::nullopt;
    if (j.contains("payment_preimage") && !j["payment_preimage"].is_null())
        r.payment_preimage = j["payment_preimage"].get<std::string>();
    else
        r.payment_preimage = std::nullopt;
    if (j.contains("change") && !j["change"].is_null())
        r.change = j["change"].get<std::vector<BlindSignature>>();
    else
        r.change = std::nullopt;
}

// NUT-05/NUT-23: POST /v1/melt/bolt11 request.
struct PostMeltBolt11Request {
    std::string quote;
    std::vector<Proof> inputs;
    std::optional<std::vector<BlindedMessage>> outputs;  // NUT-08 change outputs

    PostMeltBolt11Request() = default;
    PostMeltBolt11Request(std::string quote, std::vector<Proof> inputs,
                          std::optional<std::vector<BlindedMessage>> outputs = std::nullopt)
        : quote(std::move(quote)), inputs(std::move(inputs)), outputs(std::move(outputs)) {}
};

inline void to_json(nlohmann::json& j, const PostMeltBolt11Request& r) {
    j = {{"quote", r.quote}, {"inputs", r.inputs}};
    if (r.outputs.has_value())
        j["outputs"] = r.outputs.value();
}

inline void from_json(const nlohmann::json& j, PostMeltBolt11Request& r) {
    r.quote = j.at("quote").get<std::string>();
    r.inputs = j.at("inputs").get<std::vector<Proof>>();
    if (j.contains("outputs") && !j["outputs"].is_null())
        r.outputs = j["outputs"].get<std::vector<BlindedMessage>>();
    else
        r.outputs = std::nullopt;
}

} // namespace nutcpp::api
