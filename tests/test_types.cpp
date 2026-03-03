#include <catch2/catch_test_macros.hpp>
#include "nutcpp/types/pub_key.h"
#include "nutcpp/types/priv_key.h"
#include "nutcpp/types/tag.h"
#include "nutcpp/types/secret.h"

using namespace nutcpp;

TEST_CASE("PubKey roundtrip hex", "[types]") {
    // Known compressed public key (generator point * 1)
    std::string hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    PubKey pk(hex);
    REQUIRE(pk.to_hex() == hex);
}

TEST_CASE("PubKey equality", "[types]") {
    std::string hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    PubKey a(hex);
    PubKey b(hex);
    REQUIRE(a == b);
}

TEST_CASE("PubKey invalid hex throws", "[types]") {
    REQUIRE_THROWS_AS(PubKey("deadbeef"), std::invalid_argument);
}

TEST_CASE("PrivKey roundtrip hex", "[types]") {
    std::string hex = "0000000000000000000000000000000000000000000000000000000000000001";
    PrivKey sk(hex);
    REQUIRE(sk.to_hex() == hex);
}

TEST_CASE("PrivKey derives correct PubKey", "[types]") {
    // privkey = 1 => pubkey = generator point G
    std::string priv_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    std::string expected_pub = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    PrivKey sk(priv_hex);
    PubKey pk = sk.get_pub_key();
    REQUIRE(pk.to_hex() == expected_pub);
}

TEST_CASE("PrivKey invalid hex throws", "[types]") {
    REQUIRE_THROWS_AS(PrivKey("zzzz"), std::invalid_argument);
}

TEST_CASE("PubKey JSON roundtrip", "[types]") {
    std::string hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    PubKey pk(hex);
    nlohmann::json j = pk;
    REQUIRE(j.get<std::string>() == hex);
    PubKey pk2(j.get<std::string>());
    REQUIRE(pk == pk2);
}

TEST_CASE("PrivKey JSON roundtrip", "[types]") {
    std::string hex = "0000000000000000000000000000000000000000000000000000000000000001";
    PrivKey sk(hex);
    nlohmann::json j = sk;
    REQUIRE(j.get<std::string>() == hex);
    PrivKey sk2(j.get<std::string>());
    REQUIRE(sk.to_hex() == sk2.to_hex());
}

// --- Tag tests ---

TEST_CASE("Tag from key and values", "[types]") {
    Tag t("sigflag", {"SIG_ALL"});
    REQUIRE(t.key == "sigflag");
    REQUIRE(t.values.size() == 1);
    REQUIRE(t.values[0] == "SIG_ALL");
}

TEST_CASE("Tag from flat array", "[types]") {
    Tag t(std::vector<std::string>{"pubkeys", "pk1", "pk2"});
    REQUIRE(t.key == "pubkeys");
    REQUIRE(t.values.size() == 2);
    REQUIRE(t.values[0] == "pk1");
    REQUIRE(t.values[1] == "pk2");
}

TEST_CASE("Tag to_array roundtrip", "[types]") {
    std::vector<std::string> arr = {"locktime", "1000"};
    Tag t(arr);
    REQUIRE(t.to_array() == arr);
}

TEST_CASE("Tag empty array throws", "[types]") {
    REQUIRE_THROWS_AS(Tag(std::vector<std::string>{}), std::invalid_argument);
}

TEST_CASE("Tag key only (no values)", "[types]") {
    Tag t(std::vector<std::string>{"refund"});
    REQUIRE(t.key == "refund");
    REQUIRE(t.values.empty());
}

TEST_CASE("Tag JSON roundtrip", "[types]") {
    Tag t("sigflag", {"SIG_INPUTS"});
    nlohmann::json j = t;
    REQUIRE(j.is_array());
    REQUIRE(j[0] == "sigflag");
    REQUIRE(j[1] == "SIG_INPUTS");

    Tag t2 = j.get<Tag>();
    REQUIRE(t2.key == t.key);
    REQUIRE(t2.values == t.values);
}

// --- StringSecret tests ---

TEST_CASE("StringSecret stores value", "[types]") {
    StringSecret s("supersecret");
    REQUIRE(s.value() == "supersecret");
}

TEST_CASE("StringSecret get_bytes returns UTF-8", "[types]") {
    StringSecret s("abc");
    auto bytes = s.get_bytes();
    REQUIRE(bytes.size() == 3);
    REQUIRE(bytes[0] == 'a');
    REQUIRE(bytes[1] == 'b');
    REQUIRE(bytes[2] == 'c');
}

TEST_CASE("StringSecret empty throws", "[types]") {
    REQUIRE_THROWS_AS(StringSecret(""), std::invalid_argument);
}

TEST_CASE("StringSecret to_curve throws (not yet implemented)", "[types]") {
    StringSecret s("test");
    REQUIRE_THROWS_AS(s.to_curve(), std::runtime_error);
}

TEST_CASE("StringSecret JSON roundtrip", "[types]") {
    StringSecret s("my_secret_value");
    nlohmann::json j = s;
    REQUIRE(j.get<std::string>() == "my_secret_value");

    StringSecret s2(j.get<std::string>());
    REQUIRE(s2.value() == s.value());
}
