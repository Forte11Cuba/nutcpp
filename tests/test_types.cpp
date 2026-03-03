#include <catch2/catch_test_macros.hpp>
#include "nutcpp/types/pub_key.h"
#include "nutcpp/types/priv_key.h"

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
