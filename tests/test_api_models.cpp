#include <catch2/catch_test_macros.hpp>
#include "nutcpp/api/cashu_error.h"
#include "nutcpp/api_models/keys_response.h"
#include "nutcpp/api_models/keysets_response.h"

using namespace nutcpp;
using namespace nutcpp::api;

// ============================================================
// CashuProtocolError tests
// ============================================================

TEST_CASE("CashuProtocolError JSON roundtrip", "[api]") {
    CashuProtocolError err;
    err.detail = "Proofs already spent";
    err.code = 11001;

    nlohmann::json j = err;
    REQUIRE(j["detail"] == "Proofs already spent");
    REQUIRE(j["code"] == 11001);

    auto err2 = j.get<CashuProtocolError>();
    CHECK(err2.detail == "Proofs already spent");
    CHECK(err2.code == 11001);
}

TEST_CASE("CashuProtocolError decode from mint JSON", "[api]") {
    auto j = nlohmann::json::parse(R"json({
        "detail": "Transaction is not balanced",
        "code": 11005
    })json");

    auto err = j.get<CashuProtocolError>();
    CHECK(err.detail == "Transaction is not balanced");
    CHECK(err.code == 11005);
}

TEST_CASE("CashuProtocolException carries error", "[api]") {
    CashuProtocolError err;
    err.detail = "Keyset is not known";
    err.code = 12001;

    CashuProtocolException ex(err);
    CHECK(std::string(ex.what()) == "Keyset is not known");
    CHECK(ex.error().code == 12001);
    CHECK(ex.error().detail == "Keyset is not known");
}

TEST_CASE("CashuProtocolException can be caught as runtime_error", "[api]") {
    CashuProtocolError err;
    err.detail = "Minting is disabled";
    err.code = 20003;

    bool caught = false;
    try {
        throw CashuProtocolException(err);
    } catch (const std::runtime_error& e) {
        caught = true;
        CHECK(std::string(e.what()) == "Minting is disabled");
    }
    REQUIRE(caught);
}

// ============================================================
// GetKeysResponse tests (NUT-01)
// ============================================================

// Example from NUT-01 spec
static const char* NUT01_KEYS_JSON = R"({
    "keysets": [
        {
            "id": "009a1f293253e41e",
            "unit": "sat",
            "active": true,
            "input_fee_ppk": 100,
            "final_expiry": 1896187313,
            "keys": {
                "1": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104",
                "2": "03b0f36d6d47ce14df8a7be9137712c42bcdd960b19dd02f1d4a9703b1f31d7513",
                "4": "0366be6e026e42852498efb82014ca91e89da2e7a5bd3761bdad699fa2aec9fe09",
                "8": "0253de5237f189606f29d8a690ea719f74d65f617bb1cb6fbea34f2bc4f930016d"
            }
        }
    ]
})";

TEST_CASE("GetKeysResponse decode NUT-01 spec example", "[api][nut01]") {
    auto j = nlohmann::json::parse(NUT01_KEYS_JSON);
    auto resp = j.get<GetKeysResponse>();

    REQUIRE(resp.keysets.size() == 1);
    auto& ks = resp.keysets[0];

    CHECK(ks.id == KeysetId("009a1f293253e41e"));
    CHECK(ks.unit == "sat");
    REQUIRE(ks.active.has_value());
    CHECK(ks.active.value() == true);
    REQUIRE(ks.input_fee_ppk.has_value());
    CHECK(ks.input_fee_ppk.value() == 100);
    REQUIRE(ks.final_expiry.has_value());
    CHECK(ks.final_expiry.value() == 1896187313);
    CHECK(ks.keys.size() == 4);
    CHECK(ks.keys.at(1).to_hex() == "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104");
    CHECK(ks.keys.at(8).to_hex() == "0253de5237f189606f29d8a690ea719f74d65f617bb1cb6fbea34f2bc4f930016d");
}

TEST_CASE("GetKeysResponse JSON roundtrip", "[api][nut01]") {
    auto j = nlohmann::json::parse(NUT01_KEYS_JSON);
    auto resp = j.get<GetKeysResponse>();

    nlohmann::json j2 = resp;
    auto resp2 = j2.get<GetKeysResponse>();

    REQUIRE(resp2.keysets.size() == 1);
    CHECK(resp2.keysets[0].id == KeysetId("009a1f293253e41e"));
    CHECK(resp2.keysets[0].unit == "sat");
    CHECK(resp2.keysets[0].keys.size() == 4);
}

TEST_CASE("GetKeysResponse with optional fields absent", "[api][nut01]") {
    auto j = nlohmann::json::parse(R"({
        "keysets": [{
            "id": "009a1f293253e41e",
            "unit": "sat",
            "keys": {
                "1": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
            }
        }]
    })");

    auto resp = j.get<GetKeysResponse>();
    auto& ks = resp.keysets[0];
    CHECK_FALSE(ks.active.has_value());
    CHECK_FALSE(ks.input_fee_ppk.has_value());
    CHECK_FALSE(ks.final_expiry.has_value());
}

TEST_CASE("GetKeysResponse with null optional fields", "[api][nut01]") {
    auto j = nlohmann::json::parse(R"({
        "keysets": [{
            "id": "009a1f293253e41e",
            "unit": "sat",
            "active": null,
            "input_fee_ppk": null,
            "final_expiry": null,
            "keys": {
                "1": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
            }
        }]
    })");

    auto resp = j.get<GetKeysResponse>();
    auto& ks = resp.keysets[0];
    CHECK_FALSE(ks.active.has_value());
    CHECK_FALSE(ks.input_fee_ppk.has_value());
    CHECK_FALSE(ks.final_expiry.has_value());
}

TEST_CASE("GetKeysResponse multiple keysets", "[api][nut01]") {
    auto j = nlohmann::json::parse(R"({
        "keysets": [
            {
                "id": "009a1f293253e41e",
                "unit": "sat",
                "active": true,
                "keys": {
                    "1": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
                }
            },
            {
                "id": "00abcdef01234567",
                "unit": "usd",
                "active": false,
                "input_fee_ppk": 0,
                "keys": {
                    "1": "03b0f36d6d47ce14df8a7be9137712c42bcdd960b19dd02f1d4a9703b1f31d7513"
                }
            }
        ]
    })");

    auto resp = j.get<GetKeysResponse>();
    REQUIRE(resp.keysets.size() == 2);
    CHECK(resp.keysets[0].unit == "sat");
    CHECK(resp.keysets[0].active.value() == true);
    CHECK(resp.keysets[1].unit == "usd");
    CHECK(resp.keysets[1].active.value() == false);
    CHECK(resp.keysets[1].input_fee_ppk.value() == 0);
}

TEST_CASE("KeysResponseItem serialization omits absent optionals", "[api][nut01]") {
    KeysResponseItem item(
        KeysetId("009a1f293253e41e"), "sat",
        Keyset{{1, PubKey("02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104")}}
    );

    nlohmann::json j = item;
    CHECK(j.contains("id"));
    CHECK(j.contains("unit"));
    CHECK(j.contains("keys"));
    CHECK_FALSE(j.contains("active"));
    CHECK_FALSE(j.contains("input_fee_ppk"));
    CHECK_FALSE(j.contains("final_expiry"));
}

// ============================================================
// GetKeysetsResponse tests (NUT-02)
// ============================================================

// Example from NUT-02 spec
static const char* NUT02_KEYSETS_JSON = R"({
    "keysets": [
        {
            "id": "015ba18a8adcd02e715a58358eb618da4a4b3791151a4bee5e968bb88406ccf76a",
            "unit": "sat",
            "active": true,
            "input_fee_ppk": 100,
            "final_expiry": 2059210353
        },
        {
            "id": "012fbb01a4e200c76df911eeba3b8fe1831202914b24664f4bccbd25852a6708f8",
            "unit": "sat",
            "active": false,
            "input_fee_ppk": 0,
            "final_expiry": null
        }
    ]
})";

TEST_CASE("GetKeysetsResponse decode NUT-02 spec example", "[api][nut02]") {
    auto j = nlohmann::json::parse(NUT02_KEYSETS_JSON);
    auto resp = j.get<GetKeysetsResponse>();

    REQUIRE(resp.keysets.size() == 2);

    auto& ks0 = resp.keysets[0];
    CHECK(ks0.id == KeysetId("015ba18a8adcd02e715a58358eb618da4a4b3791151a4bee5e968bb88406ccf76a"));
    CHECK(ks0.unit == "sat");
    CHECK(ks0.active == true);
    REQUIRE(ks0.input_fee_ppk.has_value());
    CHECK(ks0.input_fee_ppk.value() == 100);
    REQUIRE(ks0.final_expiry.has_value());
    CHECK(ks0.final_expiry.value() == 2059210353);

    auto& ks1 = resp.keysets[1];
    CHECK(ks1.id == KeysetId("012fbb01a4e200c76df911eeba3b8fe1831202914b24664f4bccbd25852a6708f8"));
    CHECK(ks1.unit == "sat");
    CHECK(ks1.active == false);
    REQUIRE(ks1.input_fee_ppk.has_value());
    CHECK(ks1.input_fee_ppk.value() == 0);
    CHECK_FALSE(ks1.final_expiry.has_value());
}

TEST_CASE("GetKeysetsResponse JSON roundtrip", "[api][nut02]") {
    auto j = nlohmann::json::parse(NUT02_KEYSETS_JSON);
    auto resp = j.get<GetKeysetsResponse>();

    nlohmann::json j2 = resp;
    auto resp2 = j2.get<GetKeysetsResponse>();

    REQUIRE(resp2.keysets.size() == 2);
    CHECK(resp2.keysets[0].active == true);
    CHECK(resp2.keysets[1].active == false);
    CHECK(resp2.keysets[0].input_fee_ppk.value() == 100);
}

TEST_CASE("GetKeysetsResponse optional fields absent", "[api][nut02]") {
    auto j = nlohmann::json::parse(R"({
        "keysets": [{
            "id": "009a1f293253e41e",
            "unit": "sat",
            "active": true
        }]
    })");

    auto resp = j.get<GetKeysetsResponse>();
    auto& ks = resp.keysets[0];
    CHECK(ks.active == true);
    CHECK_FALSE(ks.input_fee_ppk.has_value());
    CHECK_FALSE(ks.final_expiry.has_value());
}

TEST_CASE("KeysetsResponseItem serialization omits absent optionals", "[api][nut02]") {
    KeysetsResponseItem item(KeysetId("009a1f293253e41e"), "sat", true);

    nlohmann::json j = item;
    CHECK(j.contains("id"));
    CHECK(j.contains("unit"));
    CHECK(j.contains("active"));
    CHECK_FALSE(j.contains("input_fee_ppk"));
    CHECK_FALSE(j.contains("final_expiry"));
}

TEST_CASE("KeysetsResponseItem active is always bool, not optional", "[api][nut02]") {
    // In NUT-02 /v1/keysets, active is required (unlike NUT-01 where it's optional)
    KeysetsResponseItem item(KeysetId("009a1f293253e41e"), "sat", false);
    nlohmann::json j = item;
    REQUIRE(j["active"].is_boolean());
    CHECK(j["active"] == false);
}
