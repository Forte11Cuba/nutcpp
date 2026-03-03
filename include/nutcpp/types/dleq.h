#pragma once

#include <nlohmann/json.hpp>
#include "nutcpp/types/priv_key.h"

namespace nutcpp {

// NUT-12: Discrete Log Equality proof {e, s}
// Proves the mint signed correctly without revealing its private key
struct DLEQ {
    PrivKey e;
    PrivKey s;

    DLEQ(const PrivKey& e, const PrivKey& s) : e(e), s(s) {}
};

// Extended DLEQ with blinding factor r (used by wallet for offline verification)
struct DLEQProof {
    PrivKey e;
    PrivKey s;
    PrivKey r;

    DLEQProof(const PrivKey& e, const PrivKey& s, const PrivKey& r)
        : e(e), s(s), r(r) {}
};

} // namespace nutcpp

namespace nlohmann {
template <>
struct adl_serializer<nutcpp::DLEQ> {
    static void to_json(json& j, const nutcpp::DLEQ& d) {
        j = {{"e", d.e}, {"s", d.s}};
    }
    static nutcpp::DLEQ from_json(const json& j) {
        return nutcpp::DLEQ(j.at("e").get<nutcpp::PrivKey>(), j.at("s").get<nutcpp::PrivKey>());
    }
};

template <>
struct adl_serializer<nutcpp::DLEQProof> {
    static void to_json(json& j, const nutcpp::DLEQProof& d) {
        j = {{"e", d.e}, {"s", d.s}, {"r", d.r}};
    }
    static nutcpp::DLEQProof from_json(const json& j) {
        return nutcpp::DLEQProof(
            j.at("e").get<nutcpp::PrivKey>(),
            j.at("s").get<nutcpp::PrivKey>(),
            j.at("r").get<nutcpp::PrivKey>()
        );
    }
};
} // namespace nlohmann
