#pragma once

#include <string>
#include <vector>
#include <optional>
#include <utility>
#include <nlohmann/json.hpp>
#include "nutcpp/types/tag.h"

namespace nutcpp::payment {

// NUT-18: Transport method for sending ecash to the receiver.
// JSON keys: "t" (type), "a" (target), "g" (tags, optional)
struct PaymentRequestTransport {
    std::string type;
    std::string target;
    std::optional<std::vector<Tag>> tags;

    PaymentRequestTransport() = default;

    PaymentRequestTransport(std::string type, std::string target,
                            std::optional<std::vector<Tag>> tags = std::nullopt)
        : type(std::move(type)), target(std::move(target)), tags(std::move(tags)) {}
};

inline void to_json(nlohmann::json& j, const PaymentRequestTransport& t) {
    j["t"] = t.type;
    j["a"] = t.target;
    if (t.tags.has_value())
        j["g"] = t.tags.value();
}

inline void from_json(const nlohmann::json& j, PaymentRequestTransport& t) {
    t.type = j.at("t").get<std::string>();
    t.target = j.at("a").get<std::string>();
    if (j.contains("g") && !j["g"].is_null())
        t.tags = j["g"].get<std::vector<Tag>>();
    else
        t.tags = std::nullopt;
}

} // namespace nutcpp::payment
