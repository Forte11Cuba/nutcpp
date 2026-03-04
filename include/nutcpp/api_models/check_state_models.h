#pragma once

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>

namespace nutcpp::api {

// NUT-07: POST /v1/checkstate request — check if proofs are spent.
struct PostCheckStateRequest {
    std::vector<std::string> Ys;    // hex-encoded Y = hash_to_curve(secret)

    PostCheckStateRequest() = default;
    explicit PostCheckStateRequest(std::vector<std::string> Ys)
        : Ys(std::move(Ys)) {}
};

inline void to_json(nlohmann::json& j, const PostCheckStateRequest& r) {
    j = {{"Ys", r.Ys}};
}

inline void from_json(const nlohmann::json& j, PostCheckStateRequest& r) {
    r.Ys = j.at("Ys").get<std::vector<std::string>>();
}

// NUT-07: single item in the states array of the response.
struct StateResponseItem {
    std::string Y;              // hex-encoded point
    std::string state;          // "UNSPENT", "PENDING", "SPENT"
    std::optional<std::string> witness;

    StateResponseItem() = default;
    StateResponseItem(std::string Y, std::string state,
                      std::optional<std::string> witness = std::nullopt)
        : Y(std::move(Y)), state(std::move(state)), witness(std::move(witness)) {}
};

inline void to_json(nlohmann::json& j, const StateResponseItem& item) {
    j = {{"Y", item.Y}, {"state", item.state}};
    if (item.witness.has_value())
        j["witness"] = item.witness.value();
}

inline void from_json(const nlohmann::json& j, StateResponseItem& item) {
    item.Y = j.at("Y").get<std::string>();
    item.state = j.at("state").get<std::string>();
    if (j.contains("witness") && !j["witness"].is_null())
        item.witness = j["witness"].get<std::string>();
    else
        item.witness = std::nullopt;
}

// NUT-07: POST /v1/checkstate response.
struct PostCheckStateResponse {
    std::vector<StateResponseItem> states;

    PostCheckStateResponse() = default;
    explicit PostCheckStateResponse(std::vector<StateResponseItem> states)
        : states(std::move(states)) {}
};

inline void to_json(nlohmann::json& j, const PostCheckStateResponse& r) {
    j = {{"states", r.states}};
}

inline void from_json(const nlohmann::json& j, PostCheckStateResponse& r) {
    r.states = j.at("states").get<std::vector<StateResponseItem>>();
}

} // namespace nutcpp::api
