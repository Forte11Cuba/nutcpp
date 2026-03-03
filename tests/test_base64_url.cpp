#include <catch2/catch_test_macros.hpp>
#include "nutcpp/encoding/base64_url.h"

using namespace nutcpp;

// ============================================================
// Basic encode/decode
// ============================================================

TEST_CASE("Base64Url encode empty", "[encoding]") {
    REQUIRE(Base64Url::encode("") == "");
}

TEST_CASE("Base64Url decode empty", "[encoding]") {
    REQUIRE(Base64Url::decode("").empty());
}

TEST_CASE("Base64Url encode 1 byte", "[encoding]") {
    // 'f' = 0x66 => Zg (no padding)
    REQUIRE(Base64Url::encode("f") == "Zg");
}

TEST_CASE("Base64Url encode 2 bytes", "[encoding]") {
    // 'fo' => Zm8
    REQUIRE(Base64Url::encode("fo") == "Zm8");
}

TEST_CASE("Base64Url encode 3 bytes", "[encoding]") {
    // 'foo' => Zm9v (exact multiple of 3, no padding needed)
    REQUIRE(Base64Url::encode("foo") == "Zm9v");
}

TEST_CASE("Base64Url encode well-known strings", "[encoding]") {
    REQUIRE(Base64Url::encode("Hello, World!") == "SGVsbG8sIFdvcmxkIQ");
    REQUIRE(Base64Url::encode("foobar") == "Zm9vYmFy");
}

TEST_CASE("Base64Url roundtrip string", "[encoding]") {
    std::string original = "The quick brown fox jumps over the lazy dog";
    auto encoded = Base64Url::encode(original);
    auto decoded = Base64Url::decode_to_string(encoded);
    REQUIRE(decoded == original);
}

TEST_CASE("Base64Url roundtrip binary", "[encoding]") {
    std::vector<unsigned char> data = {0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE};
    auto encoded = Base64Url::encode(data);
    auto decoded = Base64Url::decode(encoded);
    REQUIRE(decoded == data);
}

// ============================================================
// URL-safe characters
// ============================================================

TEST_CASE("Base64Url uses - and _ instead of + and /", "[encoding]") {
    // Bytes that produce + and / in standard base64
    // 0x3E = 62 in base64 table => '+' standard, '-' url-safe
    // 0x3F = 63 in base64 table => '/' standard, '_' url-safe
    std::vector<unsigned char> data = {0xFB, 0xEF, 0xBE}; // produces ++++  in standard
    auto encoded = Base64Url::encode(data);
    REQUIRE(encoded.find('+') == std::string::npos);
    REQUIRE(encoded.find('/') == std::string::npos);
}

TEST_CASE("Base64Url encode produces no padding", "[encoding]") {
    auto encoded = Base64Url::encode("f");  // would be "Zg==" in standard
    REQUIRE(encoded.find('=') == std::string::npos);
    REQUIRE(encoded == "Zg");
}

// ============================================================
// Decode with and without padding
// ============================================================

TEST_CASE("Base64Url decode with padding", "[encoding]") {
    // "Zg==" is standard padded form of "f"
    REQUIRE(Base64Url::decode_to_string("Zg==") == "f");
}

TEST_CASE("Base64Url decode without padding", "[encoding]") {
    REQUIRE(Base64Url::decode_to_string("Zg") == "f");
}

TEST_CASE("Base64Url decode single padding", "[encoding]") {
    // "Zm8=" is standard padded form of "fo"
    REQUIRE(Base64Url::decode_to_string("Zm8=") == "fo");
    REQUIRE(Base64Url::decode_to_string("Zm8") == "fo");
}

// ============================================================
// Decode also accepts standard base64 (+ and /)
// ============================================================

TEST_CASE("Base64Url decode accepts standard + and /", "[encoding]") {
    // Some tokens may use standard base64 chars
    auto url_safe = Base64Url::decode("--__");
    auto standard = Base64Url::decode("++//");
    REQUIRE(url_safe == standard);
}

// ============================================================
// NUT-00: V3 token serialization test vector
// ============================================================

TEST_CASE("Base64Url NUT-00 V3 token encode", "[encoding]") {
    std::string json = R"({"token":[{"mint":"https://8333.space:3338","proofs":[{"amount":2,"id":"009a1f293253e41e","secret":"407915bc212be61a77e3e6d2aeb4c727980bda51cd06a6afc29e2861768a7837","C":"02bc9097997d81afb2cc7346b5e4345a9346bd2a506eb7958598a72f0cf85163ea"},{"amount":8,"id":"009a1f293253e41e","secret":"fe15109314e61d7756b0f8ee0f23a624acaa3f4e042f61433c728c7057b931be","C":"029e8e5050b890a7d6c0968db16bc1d5d5fa040ea1de284f6ec69d61299f671059"}]}],"unit":"sat","memo":"Thank you."})";

    std::string expected =
        "eyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91LiJ9";

    REQUIRE(Base64Url::encode(json) == expected);
}

TEST_CASE("Base64Url NUT-00 V3 token decode", "[encoding]") {
    std::string encoded =
        "eyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91LiJ9";

    std::string decoded = Base64Url::decode_to_string(encoded);
    REQUIRE(decoded.find("\"mint\":\"https://8333.space:3338\"") != std::string::npos);
    REQUIRE(decoded.find("\"memo\":\"Thank you.\"") != std::string::npos);
}

TEST_CASE("Base64Url NUT-00 decode with padding", "[encoding]") {
    // From nuts/tests/00-tests.md: both padded and unpadded should decode to same content
    std::string with_padding =
        "eyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91IHZlcnkgbXVjaC4ifQ==";

    std::string without_padding =
        "eyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91IHZlcnkgbXVjaC4ifQ";

    auto decoded_padded = Base64Url::decode(with_padding);
    auto decoded_unpadded = Base64Url::decode(without_padding);
    REQUIRE(decoded_padded == decoded_unpadded);
}

// ============================================================
// Error handling
// ============================================================

TEST_CASE("Base64Url decode invalid character throws", "[encoding]") {
    REQUIRE_THROWS_AS(Base64Url::decode("abc!def"), std::invalid_argument);
    REQUIRE_THROWS_AS(Base64Url::decode("abc@def"), std::invalid_argument);
    REQUIRE_THROWS_AS(Base64Url::decode("abc def"), std::invalid_argument);
}
