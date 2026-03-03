#pragma once

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "nutcpp/types/proof.h"

namespace nutcpp {

// A group of proofs from the same mint
struct Token {
    std::string mint;
    std::vector<Proof> proofs;

    Token(const std::string& mint, const std::vector<Proof>& proofs)
        : mint(mint), proofs(proofs) {}
};

inline void to_json(nlohmann::json& j, const Token& t) {
    j = {{"mint", t.mint}, {"proofs", nlohmann::json::array()}};
    for (const auto& p : t.proofs) {
        nlohmann::json pj;
        to_json(pj, p);
        j["proofs"].push_back(pj);
    }
}

inline void from_json(const nlohmann::json& j, Token& t) {
    std::vector<Proof> proofs;
    for (const auto& pj : j.at("proofs")) {
        Proof p{0, KeysetId("000000000000"), "", PubKey("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")};
        from_json(pj, p);
        proofs.push_back(p);
    }
    t = Token(j.at("mint").get<std::string>(), proofs);
}

// Complete Cashu token: may contain proofs from multiple mints
struct CashuToken {
    std::vector<Token> tokens;
    std::optional<std::string> unit;
    std::optional<std::string> memo;

    CashuToken(const std::vector<Token>& tokens,
               std::optional<std::string> unit = std::nullopt,
               std::optional<std::string> memo = std::nullopt)
        : tokens(tokens), unit(unit), memo(memo) {}
};

inline void to_json(nlohmann::json& j, const CashuToken& ct) {
    j = {{"token", nlohmann::json::array()}};
    for (const auto& t : ct.tokens) {
        nlohmann::json tj;
        to_json(tj, t);
        j["token"].push_back(tj);
    }
    if (ct.unit.has_value())
        j["unit"] = ct.unit.value();
    if (ct.memo.has_value())
        j["memo"] = ct.memo.value();
}

inline void from_json(const nlohmann::json& j, CashuToken& ct) {
    std::vector<Token> tokens;
    for (const auto& tj : j.at("token")) {
        Token t{"", {}};
        from_json(tj, t);
        tokens.push_back(t);
    }

    std::optional<std::string> unit;
    if (j.contains("unit") && !j["unit"].is_null())
        unit = j["unit"].get<std::string>();

    std::optional<std::string> memo;
    if (j.contains("memo") && !j["memo"].is_null())
        memo = j["memo"].get<std::string>();

    ct = CashuToken(tokens, unit, memo);
}

} // namespace nutcpp
