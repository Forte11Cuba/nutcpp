#pragma once

#include <vector>
#include <nlohmann/json.hpp>
#include "nutcpp/types/blinded_message.h"
#include "nutcpp/types/blind_signature.h"

namespace nutcpp::api {

// NUT-09: POST /v1/restore request — recover blind signatures.
struct PostRestoreRequest {
    std::vector<BlindedMessage> outputs;

    PostRestoreRequest() = default;
    explicit PostRestoreRequest(std::vector<BlindedMessage> outputs)
        : outputs(std::move(outputs)) {}
};

inline void to_json(nlohmann::json& j, const PostRestoreRequest& r) {
    j = {{"outputs", r.outputs}};
}

inline void from_json(const nlohmann::json& j, PostRestoreRequest& r) {
    r.outputs = j.at("outputs").get<std::vector<BlindedMessage>>();
}

// NUT-09: POST /v1/restore response — matched outputs and their signatures.
struct PostRestoreResponse {
    std::vector<BlindedMessage> outputs;
    std::vector<BlindSignature> signatures;

    PostRestoreResponse() = default;
    PostRestoreResponse(std::vector<BlindedMessage> outputs,
                        std::vector<BlindSignature> signatures)
        : outputs(std::move(outputs)), signatures(std::move(signatures)) {}
};

inline void to_json(nlohmann::json& j, const PostRestoreResponse& r) {
    j = {{"outputs", r.outputs}, {"signatures", r.signatures}};
}

inline void from_json(const nlohmann::json& j, PostRestoreResponse& r) {
    r.outputs = j.at("outputs").get<std::vector<BlindedMessage>>();
    r.signatures = j.at("signatures").get<std::vector<BlindSignature>>();
}

} // namespace nutcpp::api
