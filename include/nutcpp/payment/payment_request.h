#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "nutcpp/payment/payment_request_transport.h"
#include "nutcpp/payment/nut10_locking_condition.h"

namespace nutcpp::payment {

// NUT-18: Payment request — supplies a sending wallet with all information
// necessary to complete a transaction.
// JSON keys: "i", "a", "u", "s", "m", "d", "nut10" (optional), "t" (always present)
struct PaymentRequest {
    std::optional<std::string> payment_id;       // "i"
    std::optional<uint64_t> amount;              // "a"
    std::optional<std::string> unit;             // "u"
    std::optional<bool> single_use;              // "s"
    std::optional<std::vector<std::string>> mints; // "m"
    std::optional<std::string> description;      // "d"
    std::vector<PaymentRequestTransport> transports; // "t"
    std::optional<Nut10LockingCondition> nut10;  // "nut10"

    PaymentRequest() = default;
};

inline void to_json(nlohmann::json& j, const PaymentRequest& r) {
    if (r.payment_id.has_value())
        j["i"] = r.payment_id.value();
    if (r.amount.has_value())
        j["a"] = r.amount.value();
    if (r.unit.has_value())
        j["u"] = r.unit.value();
    if (r.single_use.has_value())
        j["s"] = r.single_use.value();
    if (r.mints.has_value())
        j["m"] = r.mints.value();
    if (r.description.has_value())
        j["d"] = r.description.value();
    j["t"] = r.transports;
    if (r.nut10.has_value())
        j["nut10"] = r.nut10.value();
}

inline void from_json(const nlohmann::json& j, PaymentRequest& r) {
    if (j.contains("i") && !j["i"].is_null())
        r.payment_id = j["i"].get<std::string>();
    else
        r.payment_id = std::nullopt;

    if (j.contains("a") && !j["a"].is_null())
        r.amount = j["a"].get<uint64_t>();
    else
        r.amount = std::nullopt;

    if (j.contains("u") && !j["u"].is_null())
        r.unit = j["u"].get<std::string>();
    else
        r.unit = std::nullopt;

    if (j.contains("s") && !j["s"].is_null())
        r.single_use = j["s"].get<bool>();
    else
        r.single_use = std::nullopt;

    if (j.contains("m") && !j["m"].is_null())
        r.mints = j["m"].get<std::vector<std::string>>();
    else
        r.mints = std::nullopt;

    if (j.contains("d") && !j["d"].is_null())
        r.description = j["d"].get<std::string>();
    else
        r.description = std::nullopt;

    if (j.contains("t") && !j["t"].is_null())
        r.transports = j["t"].get<std::vector<PaymentRequestTransport>>();
    else
        r.transports.clear();

    if (j.contains("nut10") && !j["nut10"].is_null())
        r.nut10 = j["nut10"].get<Nut10LockingCondition>();
    else
        r.nut10 = std::nullopt;
}

} // namespace nutcpp::payment
