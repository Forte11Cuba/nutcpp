#pragma once

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "nutcpp/types/tag.h"

namespace nutcpp::payment {

// NUT-18: Locking condition for payment requests.
// Specifies the NUT-10 spending condition the payee requires.
// JSON keys: "k" (kind), "d" (data), "t" (tags, optional)
struct Nut10LockingCondition {
    std::string kind;
    std::string data;
    std::optional<std::vector<Tag>> tags;

    Nut10LockingCondition() = default;

    Nut10LockingCondition(std::string kind, std::string data,
                          std::optional<std::vector<Tag>> tags = std::nullopt)
        : kind(std::move(kind)), data(std::move(data)), tags(std::move(tags)) {}
};

inline void to_json(nlohmann::json& j, const Nut10LockingCondition& c) {
    j["k"] = c.kind;
    j["d"] = c.data;
    if (c.tags.has_value())
        j["t"] = c.tags.value();
}

inline void from_json(const nlohmann::json& j, Nut10LockingCondition& c) {
    c.kind = j.at("k").get<std::string>();
    c.data = j.at("d").get<std::string>();
    if (j.contains("t") && !j["t"].is_null())
        c.tags = j["t"].get<std::vector<Tag>>();
    else
        c.tags = std::nullopt;
}

} // namespace nutcpp::payment
