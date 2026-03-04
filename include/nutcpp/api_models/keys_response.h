#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <nlohmann/json.hpp>
#include "nutcpp/types/keyset_id.h"
#include "nutcpp/types/keyset.h"

namespace nutcpp::api {

// NUT-01: single keyset item in GET /v1/keys response.
// Contains the full keyset (amount -> pubkey map).
struct KeysResponseItem {
    KeysetId id;
    std::string unit;
    std::optional<bool> active;                 // nullable until wider adoption (DotNut)
    std::optional<uint64_t> input_fee_ppk;
    std::optional<uint64_t> final_expiry;
    Keyset keys;

    KeysResponseItem(const KeysetId& id, const std::string& unit, const Keyset& keys,
                     std::optional<bool> active = std::nullopt,
                     std::optional<uint64_t> input_fee_ppk = std::nullopt,
                     std::optional<uint64_t> final_expiry = std::nullopt)
        : id(id), unit(unit), active(active), input_fee_ppk(input_fee_ppk),
          final_expiry(final_expiry), keys(keys) {}
};

// NUT-01: GET /v1/keys response — active keysets with their public keys.
// Also used for GET /v1/keys/{keyset_id} (NUT-02).
struct GetKeysResponse {
    std::vector<KeysResponseItem> keysets;

    GetKeysResponse() = default;
    explicit GetKeysResponse(std::vector<KeysResponseItem> keysets)
        : keysets(std::move(keysets)) {}
};

} // namespace nutcpp::api

namespace nlohmann {

template <>
struct adl_serializer<nutcpp::api::KeysResponseItem> {
    static void to_json(json& j, const nutcpp::api::KeysResponseItem& item) {
        j = {
            {"id", item.id},
            {"unit", item.unit},
            {"keys", item.keys}
        };
        if (item.active.has_value())
            j["active"] = item.active.value();
        if (item.input_fee_ppk.has_value())
            j["input_fee_ppk"] = item.input_fee_ppk.value();
        if (item.final_expiry.has_value())
            j["final_expiry"] = item.final_expiry.value();
    }

    static nutcpp::api::KeysResponseItem from_json(const json& j) {
        std::optional<bool> active;
        if (j.contains("active") && !j["active"].is_null())
            active = j["active"].get<bool>();

        std::optional<uint64_t> input_fee_ppk;
        if (j.contains("input_fee_ppk") && !j["input_fee_ppk"].is_null())
            input_fee_ppk = j["input_fee_ppk"].get<uint64_t>();

        std::optional<uint64_t> final_expiry;
        if (j.contains("final_expiry") && !j["final_expiry"].is_null())
            final_expiry = j["final_expiry"].get<uint64_t>();

        return nutcpp::api::KeysResponseItem(
            j.at("id").get<nutcpp::KeysetId>(),
            j.at("unit").get<std::string>(),
            j.at("keys").get<nutcpp::Keyset>(),
            active,
            input_fee_ppk,
            final_expiry
        );
    }
};

template <>
struct adl_serializer<nutcpp::api::GetKeysResponse> {
    static void to_json(json& j, const nutcpp::api::GetKeysResponse& r) {
        j = {{"keysets", r.keysets}};
    }

    static nutcpp::api::GetKeysResponse from_json(const json& j) {
        return nutcpp::api::GetKeysResponse(
            j.at("keysets").get<std::vector<nutcpp::api::KeysResponseItem>>()
        );
    }
};

} // namespace nlohmann
