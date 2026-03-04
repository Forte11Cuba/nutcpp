#pragma once

#include <vector>
#include <nlohmann/json.hpp>
#include "nutcpp/types/proof.h"
#include "nutcpp/types/blinded_message.h"
#include "nutcpp/types/blind_signature.h"

namespace nutcpp::api {

// NUT-03: POST /v1/swap request — exchange proofs for new blind signatures.
struct PostSwapRequest {
    std::vector<Proof> inputs;
    std::vector<BlindedMessage> outputs;

    PostSwapRequest() = default;
    PostSwapRequest(std::vector<Proof> inputs, std::vector<BlindedMessage> outputs)
        : inputs(std::move(inputs)), outputs(std::move(outputs)) {}
};

inline void to_json(nlohmann::json& j, const PostSwapRequest& r) {
    j = {{"inputs", r.inputs}, {"outputs", r.outputs}};
}

inline void from_json(const nlohmann::json& j, PostSwapRequest& r) {
    r.inputs = j.at("inputs").get<std::vector<Proof>>();
    r.outputs = j.at("outputs").get<std::vector<BlindedMessage>>();
}

// NUT-03: POST /v1/swap response — new blind signatures from the mint.
struct PostSwapResponse {
    std::vector<BlindSignature> signatures;

    PostSwapResponse() = default;
    explicit PostSwapResponse(std::vector<BlindSignature> signatures)
        : signatures(std::move(signatures)) {}
};

inline void to_json(nlohmann::json& j, const PostSwapResponse& r) {
    j = {{"signatures", r.signatures}};
}

inline void from_json(const nlohmann::json& j, PostSwapResponse& r) {
    r.signatures = j.at("signatures").get<std::vector<BlindSignature>>();
}

} // namespace nutcpp::api
