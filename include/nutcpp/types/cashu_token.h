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

} // namespace nutcpp

namespace nlohmann {
template <>
struct adl_serializer<nutcpp::Token> {
    static void to_json(json& j, const nutcpp::Token& t) {
        j = {{"mint", t.mint}, {"proofs", t.proofs}};
    }
    static nutcpp::Token from_json(const json& j) {
        return nutcpp::Token(
            j.at("mint").get<std::string>(),
            j.at("proofs").get<std::vector<nutcpp::Proof>>()
        );
    }
};

template <>
struct adl_serializer<nutcpp::CashuToken> {
    static void to_json(json& j, const nutcpp::CashuToken& ct) {
        j = {{"token", ct.tokens}};
        if (ct.unit.has_value())
            j["unit"] = ct.unit.value();
        if (ct.memo.has_value())
            j["memo"] = ct.memo.value();
    }
    static nutcpp::CashuToken from_json(const json& j) {
        std::optional<std::string> unit;
        if (j.contains("unit") && !j["unit"].is_null())
            unit = j["unit"].get<std::string>();

        std::optional<std::string> memo;
        if (j.contains("memo") && !j["memo"].is_null())
            memo = j["memo"].get<std::string>();

        return nutcpp::CashuToken(
            j.at("token").get<std::vector<nutcpp::Token>>(),
            unit,
            memo
        );
    }
};
} // namespace nlohmann
