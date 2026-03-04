#include <catch2/catch_test_macros.hpp>
#include "nutcpp/encoding/token_helper.h"
#include "nutcpp/encoding/token_v3_encoder.h"
#include "nutcpp/encoding/token_v4_encoder.h"
#include "nutcpp/types/cashu_token.h"
#include "nutcpp/types/proof.h"

using namespace nutcpp;
using namespace nutcpp::encoding;
using namespace std;

// ============================================================
// Test vectors from NUT-00 spec and DotNut UnitTest1.cs:68-153
// ============================================================

// V3 token from NUT-00 spec (2 proofs, mint 8333.space, memo "Thank you.")
static const string V3_TOKEN =
    "cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4Iiwi"
    "cHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3"
    "JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2"
    "YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3Mz"
    "Q2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJh"
    "bW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkz"
    "MTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNT"
    "diOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZh"
    "MDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLC"
    "JtZW1vIjoiVGhhbmsgeW91LiJ9";

// V4 token from NUT-00 spec (3 proofs in 2 keyset groups, mint localhost)
static const string V4_TOKEN =
    "cashuBo2F0gqJhaUgA_9SLj17PgGFwgaNhYQFhc3hAYWNjMTI0MzVlN2I4NDg0YzNj"
    "ZjE4NTAxNDkyMThhZjkwZjcxNmE1MmJmNGE1ZWQzNDdlNDhlY2MxM2Y3NzM4OGFjWC"
    "ECRFODGd5IXVW-07KaZCvuWHk3WrnnpiDhHki6SCQh88-iYWlIAK0mjE0fWCZhcIKj"
    "YWECYXN4QDEzMjNkM2Q0NzA3YTU4YWQyZTIzYWRhNGU5ZjFmNDlmNWE1YjRhYzdiNz"
    "A4ZWIwZDYxZjczOGY0ODMwN2U4ZWVhY1ghAjRWqhENhLSsdHrr2Cw7AFrKUL9Ffr1X"
    "N6RBT6w659lNo2FhAWFzeEA1NmJjYmNiYjdjYzY0MDZiM2ZhNWQ1N2QyMTc0ZjRlZm"
    "Y4YjQ0MDJiMTc2OTI2ZDNhNTdkM2MzZGNiYjU5ZDU3YWNYIQJzEpxXGeWZN5qXSmJj"
    "Y8MzxWyvwObQGr5G1YCCgHicY2FtdWh0dHA6Ly9sb2NhbGhvc3Q6MzMzOGF1Y3NhdA";

// ============================================================
// V3 tests
// ============================================================

TEST_CASE("V3 decode — fields correct", "[encoding][v3]") {
    string version;
    auto result = TokenHelper::decode(V3_TOKEN, version);

    REQUIRE(version == "A");
    REQUIRE(result.memo.has_value());
    CHECK(result.memo.value() == "Thank you.");
    REQUIRE(result.unit.has_value());
    CHECK(result.unit.value() == "sat");
    REQUIRE(result.tokens.size() == 1);

    auto& token = result.tokens[0];
    CHECK(token.mint == "https://8333.space:3338");
    REQUIRE(token.proofs.size() == 2);

    CHECK(token.proofs[0].amount == 2);
    CHECK(token.proofs[0].id == KeysetId("009a1f293253e41e"));
    CHECK(token.proofs[0].secret == "407915bc212be61a77e3e6d2aeb4c727980bda51cd06a6afc29e2861768a7837");
    CHECK(token.proofs[0].C == PubKey("02bc9097997d81afb2cc7346b5e4345a9346bd2a506eb7958598a72f0cf85163ea"));

    CHECK(token.proofs[1].amount == 8);
    CHECK(token.proofs[1].id == KeysetId("009a1f293253e41e"));
    CHECK(token.proofs[1].secret == "fe15109314e61d7756b0f8ee0f23a624acaa3f4e042f61433c728c7057b931be");
    CHECK(token.proofs[1].C == PubKey("029e8e5050b890a7d6c0968db16bc1d5d5fa040ea1de284f6ec69d61299f671059"));
}

TEST_CASE("V3 roundtrip — encode produces identical string", "[encoding][v3]") {
    string version;
    auto decoded = TokenHelper::decode(V3_TOKEN, version);
    auto re_encoded = TokenHelper::encode(decoded, "A");
    CHECK(re_encoded == V3_TOKEN);
}

// ============================================================
// V4 tests
// ============================================================

TEST_CASE("V4 decode — fields correct", "[encoding][v4]") {
    string version;
    auto result = TokenHelper::decode(V4_TOKEN, version);

    REQUIRE(version == "B");
    CHECK_FALSE(result.memo.has_value());
    REQUIRE(result.unit.has_value());
    CHECK(result.unit.value() == "sat");
    REQUIRE(result.tokens.size() == 1);

    auto& token = result.tokens[0];
    CHECK(token.mint == "http://localhost:3338");
    REQUIRE(token.proofs.size() == 3);

    CHECK(token.proofs[0].amount == 1);
    CHECK(token.proofs[0].id == KeysetId("00ffd48b8f5ecf80"));
    CHECK(token.proofs[0].secret == "acc12435e7b8484c3cf1850149218af90f716a52bf4a5ed347e48ecc13f77388");
    CHECK(token.proofs[0].C == PubKey("0244538319de485d55bed3b29a642bee5879375ab9e7a620e11e48ba482421f3cf"));

    CHECK(token.proofs[1].amount == 2);
    CHECK(token.proofs[1].id == KeysetId("00ad268c4d1f5826"));
    CHECK(token.proofs[1].secret == "1323d3d4707a58ad2e23ada4e9f1f49f5a5b4ac7b708eb0d61f738f48307e8ee");
    CHECK(token.proofs[1].C == PubKey("023456aa110d84b4ac747aebd82c3b005aca50bf457ebd5737a4414fac3ae7d94d"));

    CHECK(token.proofs[2].amount == 1);
    CHECK(token.proofs[2].id == KeysetId("00ad268c4d1f5826"));
    CHECK(token.proofs[2].secret == "56bcbcbb7cc6406b3fa5d57d2174f4eff8b4402b176926d3a57d3c3dcbb59d57");
    CHECK(token.proofs[2].C == PubKey("0273129c5719e599379a974a626363c333c56cafc0e6d01abe46d5808280789c63"));
}

TEST_CASE("V4 roundtrip — encode produces identical string", "[encoding][v4]") {
    string version;
    auto decoded = TokenHelper::decode(V4_TOKEN, version);
    auto re_encoded = TokenHelper::encode(decoded, "B");
    CHECK(re_encoded == V4_TOKEN);
}

// ============================================================
// TokenHelper prefix/URI tests
// ============================================================

TEST_CASE("Decode rejects invalid prefix 'casshu'", "[encoding][helper]") {
    string version;
    CHECK_THROWS_AS(
        TokenHelper::decode(
            "casshu" + V3_TOKEN.substr(5), // "casshu" instead of "cashu"
            version),
        invalid_argument);
}

TEST_CASE("Decode rejects missing 'cashu' prefix", "[encoding][helper]") {
    string version;
    // Raw base64 payload without "cashu" prefix
    CHECK_THROWS_AS(
        TokenHelper::decode(V3_TOKEN.substr(6), version),
        invalid_argument);
}

TEST_CASE("Decode rejects unsupported version", "[encoding][helper]") {
    string version;
    CHECK_THROWS_AS(
        TokenHelper::decode("cashuZ" + V3_TOKEN.substr(6), version),
        invalid_argument);
}

TEST_CASE("Decode strips cashu: URI scheme", "[encoding][helper]") {
    string version;
    auto result = TokenHelper::decode("cashu:" + V3_TOKEN, version);
    CHECK(version == "A");
    CHECK(result.memo.value() == "Thank you.");
}

TEST_CASE("Encode with make_uri adds cashu: prefix", "[encoding][helper]") {
    string version;
    auto decoded = TokenHelper::decode(V3_TOKEN, version);
    auto uri = TokenHelper::encode(decoded, "A", true);
    CHECK(uri == "cashu:" + V3_TOKEN);
}

// ============================================================
// V4 validation tests
// ============================================================

TEST_CASE("V4 encode rejects multiple mints", "[encoding][v4]") {
    CashuToken multi_mint({
        Token("https://mint1.example.com", {
            Proof(1, KeysetId("00ffd48b8f5ecf80"), "secret1",
                  PubKey("0244538319de485d55bed3b29a642bee5879375ab9e7a620e11e48ba482421f3cf"))
        }),
        Token("https://mint2.example.com", {
            Proof(2, KeysetId("00ad268c4d1f5826"), "secret2",
                  PubKey("023456aa110d84b4ac747aebd82c3b005aca50bf457ebd5737a4414fac3ae7d94d"))
        })
    }, "sat");

    TokenV4Encoder encoder;
    CHECK_THROWS_AS(encoder.encode(multi_mint), invalid_argument);
}

TEST_CASE("V4 encode rejects missing unit", "[encoding][v4]") {
    CashuToken no_unit({
        Token("https://mint.example.com", {
            Proof(1, KeysetId("00ffd48b8f5ecf80"), "secret1",
                  PubKey("0244538319de485d55bed3b29a642bee5879375ab9e7a620e11e48ba482421f3cf"))
        })
    });

    TokenV4Encoder encoder;
    CHECK_THROWS_AS(encoder.encode(no_unit), invalid_argument);
}

// ============================================================
// Mint URL trailing slash normalization
// ============================================================

TEST_CASE("Encode strips trailing slash from mint URL", "[encoding][helper]") {
    Proof p(1, KeysetId("00ffd48b8f5ecf80"),
            "acc12435e7b8484c3cf1850149218af90f716a52bf4a5ed347e48ecc13f77388",
            PubKey("0244538319de485d55bed3b29a642bee5879375ab9e7a620e11e48ba482421f3cf"));

    CashuToken token({Token("http://localhost:3338/", {p})}, "sat");

    // Encode with trailing slash
    auto encoded = TokenHelper::encode(token, "B");

    // Decode and verify slash was stripped
    string version;
    auto decoded = TokenHelper::decode(encoded, version);
    CHECK(decoded.tokens[0].mint == "http://localhost:3338");
}
