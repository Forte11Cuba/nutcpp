#include <catch2/catch_test_macros.hpp>
#include "nutcpp/types/pub_key.h"
#include "nutcpp/types/priv_key.h"
#include "nutcpp/types/tag.h"
#include "nutcpp/types/secret.h"
#include "nutcpp/types/keyset_id.h"
#include "nutcpp/types/dleq.h"
#include "nutcpp/types/blinded_message.h"
#include "nutcpp/types/blind_signature.h"

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

// --- KeysetId tests ---

TEST_CASE("KeysetId v1 (16 chars)", "[types]") {
    KeysetId kid("00abcdef01234567");
    REQUIRE(kid.to_string() == "00abcdef01234567");
    REQUIRE(kid.get_version() == 0x00);
}

TEST_CASE("KeysetId v2 full (66 chars)", "[types]") {
    // 66 hex chars = 33 bytes (like a compressed pubkey)
    std::string id66 = "02" + std::string(64, 'a');
    KeysetId kid(id66);
    REQUIRE(kid.get_version() == 0x02);
    REQUIRE(kid.to_string() == id66);
}

TEST_CASE("KeysetId legacy (12 chars)", "[types]") {
    KeysetId kid("aabbccddeeff");
    REQUIRE(kid.to_string() == "aabbccddeeff");
}

TEST_CASE("KeysetId invalid length throws", "[types]") {
    REQUIRE_THROWS_AS(KeysetId("abcd"), std::invalid_argument);
    REQUIRE_THROWS_AS(KeysetId(""), std::invalid_argument);
    REQUIRE_THROWS_AS(KeysetId("abcdef0123456789aa"), std::invalid_argument);
}

TEST_CASE("KeysetId invalid hex throws", "[types]") {
    REQUIRE_THROWS_AS(KeysetId("00abcdefGGGG5678"), std::invalid_argument);
}

TEST_CASE("KeysetId case-insensitive equality", "[types]") {
    KeysetId a("00ABCDEF01234567");
    KeysetId b("00abcdef01234567");
    REQUIRE(a == b);
}

TEST_CASE("KeysetId get_bytes", "[types]") {
    KeysetId kid("00abcdef01234567");
    auto bytes = kid.get_bytes();
    REQUIRE(bytes.size() == 8);
    REQUIRE(bytes[0] == 0x00);
    REQUIRE(bytes[1] == 0xab);
    REQUIRE(bytes[7] == 0x67);
}

TEST_CASE("KeysetId JSON roundtrip", "[types]") {
    KeysetId kid("00abcdef01234567");
    nlohmann::json j = kid;
    REQUIRE(j.get<std::string>() == "00abcdef01234567");

    KeysetId kid2(j.get<std::string>());
    REQUIRE(kid == kid2);
}

// --- DLEQ tests ---

TEST_CASE("DLEQ JSON roundtrip", "[types]") {
    std::string e_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    std::string s_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    DLEQ d{PrivKey(e_hex), PrivKey(s_hex)};

    nlohmann::json j = d;
    REQUIRE(j["e"].get<std::string>() == e_hex);
    REQUIRE(j["s"].get<std::string>() == s_hex);

    DLEQ d2(PrivKey(j["e"].get<std::string>()), PrivKey(j["s"].get<std::string>()));
    REQUIRE(d2.e.to_hex() == e_hex);
    REQUIRE(d2.s.to_hex() == s_hex);
}

TEST_CASE("DLEQProof JSON roundtrip", "[types]") {
    std::string e_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    std::string s_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    std::string r_hex = "0000000000000000000000000000000000000000000000000000000000000003";
    DLEQProof dp{PrivKey(e_hex), PrivKey(s_hex), PrivKey(r_hex)};

    nlohmann::json j = dp;
    REQUIRE(j["e"].get<std::string>() == e_hex);
    REQUIRE(j["s"].get<std::string>() == s_hex);
    REQUIRE(j["r"].get<std::string>() == r_hex);

    DLEQProof dp2(
        PrivKey(j["e"].get<std::string>()),
        PrivKey(j["s"].get<std::string>()),
        PrivKey(j["r"].get<std::string>())
    );
    REQUIRE(dp2.e.to_hex() == e_hex);
    REQUIRE(dp2.s.to_hex() == s_hex);
    REQUIRE(dp2.r.to_hex() == r_hex);
}

// --- BlindedMessage tests ---

TEST_CASE("BlindedMessage basic construction", "[types]") {
    std::string pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    BlindedMessage bm{64, KeysetId("00abcdef01234567"), PubKey(pk_hex)};
    REQUIRE(bm.amount == 64);
    REQUIRE(bm.id.to_string() == "00abcdef01234567");
    REQUIRE(bm.B_.to_hex() == pk_hex);
    REQUIRE(!bm.witness.has_value());
}

TEST_CASE("BlindedMessage with witness", "[types]") {
    std::string pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    BlindedMessage bm{8, KeysetId("00abcdef01234567"), PubKey(pk_hex), "sig_data"};
    REQUIRE(bm.witness.has_value());
    REQUIRE(bm.witness.value() == "sig_data");
}

TEST_CASE("BlindedMessage JSON roundtrip", "[types]") {
    std::string pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    BlindedMessage bm{16, KeysetId("00abcdef01234567"), PubKey(pk_hex)};

    nlohmann::json j = bm;
    REQUIRE(j["amount"] == 16);
    REQUIRE(j["id"] == "00abcdef01234567");
    REQUIRE(j["B_"] == pk_hex);
    REQUIRE(!j.contains("witness"));

    BlindedMessage bm2{0, KeysetId("00abcdef01234567"), PubKey(pk_hex)};
    from_json(j, bm2);
    REQUIRE(bm2.amount == 16);
    REQUIRE(bm2.id == KeysetId("00abcdef01234567"));
    REQUIRE(bm2.B_.to_hex() == pk_hex);
    REQUIRE(!bm2.witness.has_value());
}

TEST_CASE("BlindedMessage JSON with witness", "[types]") {
    std::string pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    BlindedMessage bm{32, KeysetId("00abcdef01234567"), PubKey(pk_hex), "witness_value"};

    nlohmann::json j = bm;
    REQUIRE(j["witness"] == "witness_value");

    BlindedMessage bm2{0, KeysetId("00abcdef01234567"), PubKey(pk_hex)};
    from_json(j, bm2);
    REQUIRE(bm2.amount == 32);
    REQUIRE(bm2.id == KeysetId("00abcdef01234567"));
    REQUIRE(bm2.B_.to_hex() == pk_hex);
    REQUIRE(bm2.witness.has_value());
    REQUIRE(bm2.witness.value() == "witness_value");
}

// --- BlindSignature tests ---

TEST_CASE("BlindSignature basic construction", "[types]") {
    std::string pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    BlindSignature bs{64, KeysetId("00abcdef01234567"), PubKey(pk_hex)};
    REQUIRE(bs.amount == 64);
    REQUIRE(bs.id.to_string() == "00abcdef01234567");
    REQUIRE(bs.C_.to_hex() == pk_hex);
    REQUIRE(!bs.dleq.has_value());
}

TEST_CASE("BlindSignature JSON roundtrip", "[types]") {
    std::string pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    BlindSignature bs{16, KeysetId("00abcdef01234567"), PubKey(pk_hex)};

    nlohmann::json j = bs;
    REQUIRE(j["amount"] == 16);
    REQUIRE(j["id"] == "00abcdef01234567");
    REQUIRE(j["C_"] == pk_hex);
    REQUIRE(!j.contains("dleq"));

    BlindSignature bs2{0, KeysetId("00abcdef01234567"), PubKey(pk_hex)};
    from_json(j, bs2);
    REQUIRE(bs2.amount == 16);
    REQUIRE(bs2.id == KeysetId("00abcdef01234567"));
    REQUIRE(bs2.C_.to_hex() == pk_hex);
    REQUIRE(!bs2.dleq.has_value());
}

TEST_CASE("BlindSignature JSON with DLEQ", "[types]") {
    std::string pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    std::string e_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    std::string s_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    std::string r_hex = "0000000000000000000000000000000000000000000000000000000000000003";

    DLEQProof dleq{PrivKey(e_hex), PrivKey(s_hex), PrivKey(r_hex)};
    BlindSignature bs{32, KeysetId("00abcdef01234567"), PubKey(pk_hex), dleq};

    nlohmann::json j = bs;
    REQUIRE(j.contains("dleq"));
    REQUIRE(j["dleq"]["e"] == e_hex);
    REQUIRE(j["dleq"]["s"] == s_hex);
    REQUIRE(j["dleq"]["r"] == r_hex);

    BlindSignature bs2{0, KeysetId("00abcdef01234567"), PubKey(pk_hex)};
    from_json(j, bs2);
    REQUIRE(bs2.amount == 32);
    REQUIRE(bs2.id == KeysetId("00abcdef01234567"));
    REQUIRE(bs2.C_.to_hex() == pk_hex);
    REQUIRE(bs2.dleq.has_value());
    REQUIRE(bs2.dleq.value().e.to_hex() == e_hex);
    REQUIRE(bs2.dleq.value().s.to_hex() == s_hex);
    REQUIRE(bs2.dleq.value().r.to_hex() == r_hex);
}

TEST_CASE("BlindSignature JSON with explicit null dleq", "[types]") {
    std::string pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    std::string e_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    std::string s_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    std::string r_hex = "0000000000000000000000000000000000000000000000000000000000000003";
    BlindSignature bs{16, KeysetId("00abcdef01234567"), PubKey(pk_hex)};

    nlohmann::json j = bs;
    j["dleq"] = nullptr;

    // Start with dleq present to verify from_json clears it
    DLEQProof existing{PrivKey(e_hex), PrivKey(s_hex), PrivKey(r_hex)};
    BlindSignature bs2{0, KeysetId("00abcdef01234567"), PubKey(pk_hex), existing};
    from_json(j, bs2);
    REQUIRE(bs2.amount == 16);
    REQUIRE(bs2.id == KeysetId("00abcdef01234567"));
    REQUIRE(bs2.C_.to_hex() == pk_hex);
    REQUIRE(!bs2.dleq.has_value());
}
