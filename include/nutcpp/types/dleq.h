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

inline void to_json(nlohmann::json& j, const DLEQ& d) {
    j = {{"e", d.e}, {"s", d.s}};
}

inline void from_json(const nlohmann::json& j, DLEQ& d) {
    d = DLEQ(
        PrivKey(j.at("e").get<std::string>()),
        PrivKey(j.at("s").get<std::string>())
    );
}

// Extended DLEQ with blinding factor r (used by wallet for offline verification)
struct DLEQProof {
    PrivKey e;
    PrivKey s;
    PrivKey r;

    DLEQProof(const PrivKey& e, const PrivKey& s, const PrivKey& r)
        : e(e), s(s), r(r) {}
};

inline void to_json(nlohmann::json& j, const DLEQProof& d) {
    j = {{"e", d.e}, {"s", d.s}, {"r", d.r}};
}

inline void from_json(const nlohmann::json& j, DLEQProof& d) {
    d = DLEQProof(
        PrivKey(j.at("e").get<std::string>()),
        PrivKey(j.at("s").get<std::string>()),
        PrivKey(j.at("r").get<std::string>())
    );
}

} // namespace nutcpp
