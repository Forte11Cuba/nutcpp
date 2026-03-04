#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <nlohmann/json.hpp>
#include "nutcpp/types/keyset_id.h"

namespace nutcpp::api {

// NUT-02: single keyset item in GET /v1/keysets response.
// Does NOT contain the actual keys (use GET /v1/keys/{id} for that).
struct KeysetsResponseItem {
    KeysetId id;
    std::string unit;
    bool active;
    std::optional<uint64_t> input_fee_ppk;      // 0 if not present (per spec)
    std::optional<uint64_t> final_expiry;

    KeysetsResponseItem(const KeysetId& id, const std::string& unit, bool active,
                        std::optional<uint64_t> input_fee_ppk = std::nullopt,
                        std::optional<uint64_t> final_expiry = std::nullopt)
        : id(id), unit(unit), active(active),
          input_fee_ppk(input_fee_ppk), final_expiry(final_expiry) {}
};

// NUT-02: GET /v1/keysets response — all keysets (active and inactive).
struct GetKeysetsResponse {
    std::vector<KeysetsResponseItem> keysets;

    GetKeysetsResponse() = default;
    explicit GetKeysetsResponse(std::vector<KeysetsResponseItem> keysets)
        : keysets(std::move(keysets)) {}
};

} // namespace nutcpp::api

namespace nlohmann {

template <>
struct adl_serializer<nutcpp::api::KeysetsResponseItem> {
    static void to_json(json& j, const nutcpp::api::KeysetsResponseItem& item) {
        j = {
            {"id", item.id},
            {"unit", item.unit},
            {"active", item.active}
        };
        if (item.input_fee_ppk.has_value())
            j["input_fee_ppk"] = item.input_fee_ppk.value();
        if (item.final_expiry.has_value())
            j["final_expiry"] = item.final_expiry.value();
    }

    static nutcpp::api::KeysetsResponseItem from_json(const json& j) {
        std::optional<uint64_t> input_fee_ppk;
        if (j.contains("input_fee_ppk") && !j["input_fee_ppk"].is_null())
            input_fee_ppk = j["input_fee_ppk"].get<uint64_t>();

        std::optional<uint64_t> final_expiry;
        if (j.contains("final_expiry") && !j["final_expiry"].is_null())
            final_expiry = j["final_expiry"].get<uint64_t>();

        return nutcpp::api::KeysetsResponseItem(
            j.at("id").get<nutcpp::KeysetId>(),
            j.at("unit").get<std::string>(),
            j.at("active").get<bool>(),
            input_fee_ppk,
            final_expiry
        );
    }
};

template <>
struct adl_serializer<nutcpp::api::GetKeysetsResponse> {
    static void to_json(json& j, const nutcpp::api::GetKeysetsResponse& r) {
        j = {{"keysets", r.keysets}};
    }

    static nutcpp::api::GetKeysetsResponse from_json(const json& j) {
        return nutcpp::api::GetKeysetsResponse(
            j.at("keysets").get<std::vector<nutcpp::api::KeysetsResponseItem>>()
        );
    }
};

} // namespace nlohmann
