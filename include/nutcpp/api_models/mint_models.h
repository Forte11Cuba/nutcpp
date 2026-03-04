#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <nlohmann/json.hpp>
#include "nutcpp/types/blinded_message.h"
#include "nutcpp/types/blind_signature.h"

namespace nutcpp::api {

// NUT-04/NUT-23: POST /v1/mint/quote/bolt11 request.
struct PostMintQuoteBolt11Request {
    uint64_t amount = 0;
    std::string unit;
    std::optional<std::string> description;

    PostMintQuoteBolt11Request() = default;
    PostMintQuoteBolt11Request(uint64_t amount, std::string unit,
                               std::optional<std::string> description = std::nullopt)
        : amount(amount), unit(std::move(unit)), description(std::move(description)) {}
};

inline void to_json(nlohmann::json& j, const PostMintQuoteBolt11Request& r) {
    j = {{"amount", r.amount}, {"unit", r.unit}};
    if (r.description.has_value())
        j["description"] = r.description.value();
}

inline void from_json(const nlohmann::json& j, PostMintQuoteBolt11Request& r) {
    r.amount = j.at("amount").get<uint64_t>();
    r.unit = j.at("unit").get<std::string>();
    if (j.contains("description") && !j["description"].is_null())
        r.description = j["description"].get<std::string>();
    else
        r.description = std::nullopt;
}

// NUT-04/NUT-23: POST /v1/mint/quote/bolt11 response (also GET /v1/mint/quote/bolt11/{quote_id}).
struct PostMintQuoteBolt11Response {
    std::string quote;
    std::string request;
    std::string state;
    std::optional<uint64_t> expiry;
    std::optional<uint64_t> amount;      // recently added to spec; optional for backward compat
    std::optional<std::string> unit;     // recently added to spec; optional for backward compat

    PostMintQuoteBolt11Response() = default;
};

inline void to_json(nlohmann::json& j, const PostMintQuoteBolt11Response& r) {
    j = {{"quote", r.quote}, {"request", r.request}, {"state", r.state}};
    if (r.expiry.has_value())
        j["expiry"] = r.expiry.value();
    if (r.amount.has_value())
        j["amount"] = r.amount.value();
    if (r.unit.has_value())
        j["unit"] = r.unit.value();
}

inline void from_json(const nlohmann::json& j, PostMintQuoteBolt11Response& r) {
    r.quote = j.at("quote").get<std::string>();
    r.request = j.at("request").get<std::string>();
    r.state = j.at("state").get<std::string>();
    if (j.contains("expiry") && !j["expiry"].is_null())
        r.expiry = j["expiry"].get<uint64_t>();
    else
        r.expiry = std::nullopt;
    if (j.contains("amount") && !j["amount"].is_null())
        r.amount = j["amount"].get<uint64_t>();
    else
        r.amount = std::nullopt;
    if (j.contains("unit") && !j["unit"].is_null())
        r.unit = j["unit"].get<std::string>();
    else
        r.unit = std::nullopt;
}

// NUT-04: POST /v1/mint/{method} request — exchange a paid quote for blind signatures.
struct PostMintRequest {
    std::string quote;
    std::vector<BlindedMessage> outputs;

    PostMintRequest() = default;
    PostMintRequest(std::string quote, std::vector<BlindedMessage> outputs)
        : quote(std::move(quote)), outputs(std::move(outputs)) {}
};

inline void to_json(nlohmann::json& j, const PostMintRequest& r) {
    j = {{"quote", r.quote}, {"outputs", r.outputs}};
}

inline void from_json(const nlohmann::json& j, PostMintRequest& r) {
    r.quote = j.at("quote").get<std::string>();
    r.outputs = j.at("outputs").get<std::vector<BlindedMessage>>();
}

// NUT-04: POST /v1/mint/{method} response — blind signatures from the mint.
struct PostMintResponse {
    std::vector<BlindSignature> signatures;

    PostMintResponse() = default;
    explicit PostMintResponse(std::vector<BlindSignature> signatures)
        : signatures(std::move(signatures)) {}
};

inline void to_json(nlohmann::json& j, const PostMintResponse& r) {
    j = {{"signatures", r.signatures}};
}

inline void from_json(const nlohmann::json& j, PostMintResponse& r) {
    r.signatures = j.at("signatures").get<std::vector<BlindSignature>>();
}

} // namespace nutcpp::api
