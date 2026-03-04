#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <cstdint>
#include <utility>
#include <nlohmann/json.hpp>

namespace nutcpp::api {

// NUT-06: contact entry in GetInfoResponse.
struct ContactInfo {
    std::string method;
    std::string info;

    ContactInfo() = default;
    ContactInfo(std::string method, std::string info)
        : method(std::move(method)), info(std::move(info)) {}
};

inline void to_json(nlohmann::json& j, const ContactInfo& c) {
    j = {{"method", c.method}, {"info", c.info}};
}

inline void from_json(const nlohmann::json& j, ContactInfo& c) {
    c.method = j.at("method").get<std::string>();
    c.info = j.at("info").get<std::string>();
}

// NUT-04/NUT-05 settings: method-unit pair with optional limits.
struct MethodSetting {
    std::string method;
    std::string unit;
    std::optional<uint64_t> min_amount;
    std::optional<uint64_t> max_amount;
    std::optional<nlohmann::json> options;

    MethodSetting() = default;
    MethodSetting(std::string method, std::string unit,
                  std::optional<uint64_t> min_amount = std::nullopt,
                  std::optional<uint64_t> max_amount = std::nullopt,
                  std::optional<nlohmann::json> options = std::nullopt)
        : method(std::move(method)), unit(std::move(unit)),
          min_amount(min_amount), max_amount(max_amount),
          options(std::move(options)) {}
};

inline void to_json(nlohmann::json& j, const MethodSetting& s) {
    j = {{"method", s.method}, {"unit", s.unit}};
    if (s.min_amount.has_value())
        j["min_amount"] = s.min_amount.value();
    if (s.max_amount.has_value())
        j["max_amount"] = s.max_amount.value();
    if (s.options.has_value())
        j["options"] = s.options.value();
}

inline void from_json(const nlohmann::json& j, MethodSetting& s) {
    s.method = j.at("method").get<std::string>();
    s.unit = j.at("unit").get<std::string>();
    if (j.contains("min_amount") && !j["min_amount"].is_null())
        s.min_amount = j["min_amount"].get<uint64_t>();
    else
        s.min_amount = std::nullopt;
    if (j.contains("max_amount") && !j["max_amount"].is_null())
        s.max_amount = j["max_amount"].get<uint64_t>();
    else
        s.max_amount = std::nullopt;
    if (j.contains("options") && !j["options"].is_null())
        s.options = j["options"];
    else
        s.options = std::nullopt;
}

// NUT-06: GET /v1/info response — mint information.
struct GetInfoResponse {
    std::optional<std::string> name;
    std::optional<std::string> pubkey;
    std::optional<std::string> version;
    std::optional<std::string> description;
    std::optional<std::string> description_long;
    std::optional<std::vector<ContactInfo>> contact;
    std::optional<std::string> motd;
    std::optional<std::string> icon_url;
    std::optional<std::vector<std::string>> urls;
    std::optional<uint64_t> time;
    std::optional<std::string> tos_url;
    std::optional<std::map<std::string, nlohmann::json>> nuts;

    GetInfoResponse() = default;
};

inline void to_json(nlohmann::json& j, const GetInfoResponse& r) {
    j = nlohmann::json::object();
    if (r.name.has_value())             j["name"] = r.name.value();
    if (r.pubkey.has_value())           j["pubkey"] = r.pubkey.value();
    if (r.version.has_value())          j["version"] = r.version.value();
    if (r.description.has_value())      j["description"] = r.description.value();
    if (r.description_long.has_value()) j["description_long"] = r.description_long.value();
    if (r.contact.has_value())          j["contact"] = r.contact.value();
    if (r.motd.has_value())             j["motd"] = r.motd.value();
    if (r.icon_url.has_value())         j["icon_url"] = r.icon_url.value();
    if (r.urls.has_value())             j["urls"] = r.urls.value();
    if (r.time.has_value())             j["time"] = r.time.value();
    if (r.tos_url.has_value())          j["tos_url"] = r.tos_url.value();
    if (r.nuts.has_value())             j["nuts"] = r.nuts.value();
}

inline void from_json(const nlohmann::json& j, GetInfoResponse& r) {
    auto opt_str = [&](const char* key, std::optional<std::string>& out) {
        if (j.contains(key) && !j[key].is_null())
            out = j[key].get<std::string>();
        else
            out = std::nullopt;
    };

    opt_str("name", r.name);
    opt_str("pubkey", r.pubkey);
    opt_str("version", r.version);
    opt_str("description", r.description);
    opt_str("description_long", r.description_long);
    opt_str("motd", r.motd);
    opt_str("icon_url", r.icon_url);
    opt_str("tos_url", r.tos_url);

    if (j.contains("contact") && !j["contact"].is_null())
        r.contact = j["contact"].get<std::vector<ContactInfo>>();
    else
        r.contact = std::nullopt;

    if (j.contains("urls") && !j["urls"].is_null())
        r.urls = j["urls"].get<std::vector<std::string>>();
    else
        r.urls = std::nullopt;

    if (j.contains("time") && !j["time"].is_null())
        r.time = j["time"].get<uint64_t>();
    else
        r.time = std::nullopt;

    if (j.contains("nuts") && !j["nuts"].is_null())
        r.nuts = j["nuts"].get<std::map<std::string, nlohmann::json>>();
    else
        r.nuts = std::nullopt;
}

} // namespace nutcpp::api
