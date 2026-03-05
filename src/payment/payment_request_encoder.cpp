#include "nutcpp/payment/payment_request_encoder.h"
#include "nutcpp/encoding/base64_url.h"
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <algorithm>
#include <cctype>

using namespace std;
using ordered_json = nlohmann::ordered_json;

namespace nutcpp::payment {

// ====== CBOR helpers ======

static ordered_json tags_to_cbor(const vector<Tag>& tags) {
    auto arr = ordered_json::array();
    for (auto& tag : tags) {
        auto tag_arr = ordered_json::array();
        tag_arr.push_back(tag.key);
        for (auto& v : tag.values)
            tag_arr.push_back(v);
        arr.push_back(tag_arr);
    }
    return arr;
}

static vector<Tag> tags_from_cbor(const ordered_json& arr) {
    if (!arr.is_array())
        throw invalid_argument("Invalid tag container: expected array");

    vector<Tag> tags;
    for (auto& item : arr) {
        if (!item.is_array() || item.empty())
            throw invalid_argument("Invalid tag entry: expected non-empty array");
        vector<string> flat;
        flat.reserve(item.size());
        for (auto& elem : item)
            flat.push_back(elem.get<string>());
        tags.emplace_back(flat);
    }
    return tags;
}

// ====== Encode ======

string PaymentRequestEncoder::encode(const PaymentRequest& request) {
    ordered_json cbor;

    // Optional fields first (DotNut order: i, a, u, s, m, d, nut10, t)
    if (request.payment_id.has_value())
        cbor["i"] = request.payment_id.value();
    if (request.amount.has_value())
        cbor["a"] = request.amount.value();
    if (request.unit.has_value())
        cbor["u"] = request.unit.value();
    if (request.single_use.has_value())
        cbor["s"] = request.single_use.value();
    if (request.mints.has_value())
        cbor["m"] = request.mints.value();
    if (request.description.has_value())
        cbor["d"] = request.description.value();

    // NUT-10 locking condition
    if (request.nut10.has_value()) {
        ordered_json nut10_obj;
        nut10_obj["k"] = request.nut10->kind;
        nut10_obj["d"] = request.nut10->data;
        if (request.nut10->tags.has_value())
            nut10_obj["t"] = tags_to_cbor(request.nut10->tags.value());
        cbor["nut10"] = nut10_obj;
    }

    // Transports (always last, matching DotNut)
    auto transports_arr = ordered_json::array();
    for (auto& transport : request.transports) {
        ordered_json t;
        t["t"] = transport.type;
        t["a"] = transport.target;
        if (transport.tags.has_value())
            t["g"] = tags_to_cbor(transport.tags.value());
        transports_arr.push_back(t);
    }
    cbor["t"] = transports_arr;

    auto cbor_bytes = ordered_json::to_cbor(cbor);
    return "creqA" + Base64Url::encode(cbor_bytes.data(), cbor_bytes.size());
}

// ====== Decode ======

PaymentRequest PaymentRequestEncoder::decode(const string& payload) {
    auto raw = Base64Url::decode(payload);
    auto cbor = ordered_json::from_cbor(raw);

    PaymentRequest r;

    if (cbor.contains("i"))
        r.payment_id = cbor["i"].get<string>();
    if (cbor.contains("a"))
        r.amount = cbor["a"].get<uint64_t>();
    if (cbor.contains("u"))
        r.unit = cbor["u"].get<string>();
    if (cbor.contains("s"))
        r.single_use = cbor["s"].get<bool>();
    if (cbor.contains("m")) {
        vector<string> mints;
        for (auto& m : cbor["m"])
            mints.push_back(m.get<string>());
        r.mints = mints;
    }
    if (cbor.contains("d"))
        r.description = cbor["d"].get<string>();

    if (cbor.contains("t")) {
        for (auto& item : cbor["t"]) {
            PaymentRequestTransport transport;
            if (item.contains("t"))
                transport.type = item["t"].get<string>();
            if (item.contains("a"))
                transport.target = item["a"].get<string>();
            if (item.contains("g"))
                transport.tags = tags_from_cbor(item["g"]);
            r.transports.push_back(transport);
        }
    }

    if (cbor.contains("nut10")) {
        auto& n = cbor["nut10"];
        if (!n.contains("k") || !n.contains("d"))
            throw invalid_argument("Invalid nut10: missing required fields 'k' and/or 'd'");
        Nut10LockingCondition nut10;
        nut10.kind = n["k"].get<string>();
        nut10.data = n["d"].get<string>();
        if (n.contains("t"))
            nut10.tags = tags_from_cbor(n["t"]);
        r.nut10 = nut10;
    }

    return r;
}

// ====== Parse (dispatch) ======

static bool starts_with_ci(const string& str, const string& prefix) {
    if (str.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (tolower(static_cast<unsigned char>(str[i])) !=
            tolower(static_cast<unsigned char>(prefix[i])))
            return false;
    }
    return true;
}

PaymentRequest PaymentRequestEncoder::parse(const string& creq) {
    if (starts_with_ci(creq, "creqA")) {
        return decode(creq.substr(5));
    }

    // creqB will be handled here in PR 7e
    if (starts_with_ci(creq, "creqb1") || starts_with_ci(creq, "CREQB1")) {
        throw invalid_argument("Bech32m payment requests (creqB) not yet implemented");
    }

    throw invalid_argument("Invalid payment request format");
}

} // namespace nutcpp::payment
