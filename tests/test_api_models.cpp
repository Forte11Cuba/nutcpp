#include <catch2/catch_test_macros.hpp>
#include "nutcpp/api/cashu_error.h"
#include "nutcpp/api_models/keys_response.h"
#include "nutcpp/api_models/keysets_response.h"
#include "nutcpp/api_models/swap_models.h"
#include "nutcpp/api_models/mint_models.h"
#include "nutcpp/api_models/melt_models.h"
#include "nutcpp/api_models/check_state_models.h"
#include "nutcpp/api_models/restore_models.h"
#include "nutcpp/api_models/info_response.h"

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

// ============================================================
// PostSwapRequest/Response tests (NUT-03)
// ============================================================

TEST_CASE("PostSwapRequest JSON roundtrip", "[api][nut03]") {
    auto j = nlohmann::json::parse(R"json({
        "inputs": [{
            "amount": 8,
            "id": "009a1f293253e41e",
            "secret": "secret_string",
            "C": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
        }],
        "outputs": [{
            "amount": 4,
            "id": "009a1f293253e41e",
            "B_": "03b0f36d6d47ce14df8a7be9137712c42bcdd960b19dd02f1d4a9703b1f31d7513"
        },
        {
            "amount": 4,
            "id": "009a1f293253e41e",
            "B_": "0366be6e026e42852498efb82014ca91e89da2e7a5bd3761bdad699fa2aec9fe09"
        }]
    })json");

    auto req = j.get<PostSwapRequest>();
    REQUIRE(req.inputs.size() == 1);
    REQUIRE(req.outputs.size() == 2);
    CHECK(req.inputs[0].amount == 8);
    CHECK(req.outputs[0].amount == 4);

    nlohmann::json j2 = req;
    auto req2 = j2.get<PostSwapRequest>();
    CHECK(req2.inputs.size() == 1);
    CHECK(req2.outputs.size() == 2);
}

TEST_CASE("PostSwapResponse JSON roundtrip", "[api][nut03]") {
    auto j = nlohmann::json::parse(R"json({
        "signatures": [{
            "id": "009a1f293253e41e",
            "amount": 4,
            "C_": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
        }]
    })json");

    auto resp = j.get<PostSwapResponse>();
    REQUIRE(resp.signatures.size() == 1);
    CHECK(resp.signatures[0].amount == 4);

    nlohmann::json j2 = resp;
    CHECK(j2["signatures"].size() == 1);
}

// ============================================================
// PostMintQuoteBolt11 tests (NUT-04/NUT-23)
// ============================================================

TEST_CASE("PostMintQuoteBolt11Request JSON roundtrip", "[api][nut04]") {
    PostMintQuoteBolt11Request req(10, "sat");

    nlohmann::json j = req;
    CHECK(j["amount"] == 10);
    CHECK(j["unit"] == "sat");
    CHECK_FALSE(j.contains("description"));

    auto req2 = j.get<PostMintQuoteBolt11Request>();
    CHECK(req2.amount == 10);
    CHECK(req2.unit == "sat");
    CHECK_FALSE(req2.description.has_value());
}

TEST_CASE("PostMintQuoteBolt11Request with description", "[api][nut04]") {
    PostMintQuoteBolt11Request req(100, "sat", "Payment for coffee");

    nlohmann::json j = req;
    CHECK(j["amount"] == 100);
    CHECK(j["unit"] == "sat");
    REQUIRE(j.contains("description"));
    CHECK(j["description"] == "Payment for coffee");

    auto req2 = j.get<PostMintQuoteBolt11Request>();
    REQUIRE(req2.description.has_value());
    CHECK(req2.description.value() == "Payment for coffee");
}

// NUT-23 spec example
TEST_CASE("PostMintQuoteBolt11Response decode NUT-23 spec example", "[api][nut04]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "DSGLX9kevM...",
        "request": "lnbc100n1pj4apw9...",
        "amount": 10,
        "unit": "sat",
        "state": "UNPAID",
        "expiry": 1701704757
    })json");

    auto resp = j.get<PostMintQuoteBolt11Response>();
    CHECK(resp.quote == "DSGLX9kevM...");
    CHECK(resp.request == "lnbc100n1pj4apw9...");
    CHECK(resp.state == "UNPAID");
    REQUIRE(resp.expiry.has_value());
    CHECK(resp.expiry.value() == 1701704757);
    REQUIRE(resp.amount.has_value());
    CHECK(resp.amount.value() == 10);
    REQUIRE(resp.unit.has_value());
    CHECK(resp.unit.value() == "sat");
}

TEST_CASE("PostMintQuoteBolt11Response JSON roundtrip", "[api][nut04]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "test-id",
        "request": "lnbc...",
        "state": "PAID",
        "expiry": 1640995200,
        "amount": 1000,
        "unit": "sat"
    })json");

    auto resp = j.get<PostMintQuoteBolt11Response>();
    nlohmann::json j2 = resp;
    auto resp2 = j2.get<PostMintQuoteBolt11Response>();

    CHECK(resp2.quote == "test-id");
    CHECK(resp2.state == "PAID");
    CHECK(resp2.expiry.value() == 1640995200);
    CHECK(resp2.amount.value() == 1000);
    CHECK(resp2.unit.value() == "sat");
}

// Mirrors DotNut NullExpiryTests_PostMintQuoteBolt11Response
TEST_CASE("PostMintQuoteBolt11Response with null expiry", "[api][nut04]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "test-quote-id",
        "request": "test-request",
        "state": "PAID",
        "expiry": null
    })json");

    auto resp = j.get<PostMintQuoteBolt11Response>();
    CHECK(resp.quote == "test-quote-id");
    CHECK(resp.state == "PAID");
    CHECK_FALSE(resp.expiry.has_value());
    CHECK_FALSE(resp.amount.has_value());
    CHECK_FALSE(resp.unit.has_value());
}

TEST_CASE("PostMintQuoteBolt11Response with absent expiry", "[api][nut04]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "test-quote-id",
        "request": "test-request",
        "state": "UNPAID"
    })json");

    auto resp = j.get<PostMintQuoteBolt11Response>();
    CHECK_FALSE(resp.expiry.has_value());
}

TEST_CASE("PostMintQuoteBolt11Response serialization omits absent optionals", "[api][nut04]") {
    PostMintQuoteBolt11Response resp;
    resp.quote = "q1";
    resp.request = "lnbc...";
    resp.state = "UNPAID";

    nlohmann::json j = resp;
    CHECK(j.contains("quote"));
    CHECK(j.contains("request"));
    CHECK(j.contains("state"));
    CHECK_FALSE(j.contains("expiry"));
    CHECK_FALSE(j.contains("amount"));
    CHECK_FALSE(j.contains("unit"));
}

// NUT-04 generic mint request/response (NUT-23 spec example)
TEST_CASE("PostMintRequest decode NUT-23 spec example", "[api][nut04]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "DSGLX9kevM...",
        "outputs": [
            {
                "amount": 8,
                "id": "009a1f293253e41e",
                "B_": "035015e6d7ade60ba8426cefaf1832bbd27257636e44a76b922d78e79b47cb689d"
            },
            {
                "amount": 2,
                "id": "009a1f293253e41e",
                "B_": "0288d7649652d0a83fc9c966c969fb217f15904431e61a44b14999fabc1b5d9ac6"
            }
        ]
    })json");

    auto req = j.get<PostMintRequest>();
    CHECK(req.quote == "DSGLX9kevM...");
    REQUIRE(req.outputs.size() == 2);
    CHECK(req.outputs[0].amount == 8);
    CHECK(req.outputs[1].amount == 2);
}

TEST_CASE("PostMintResponse decode NUT-23 spec example", "[api][nut04]") {
    auto j = nlohmann::json::parse(R"json({
        "signatures": [
            {
                "id": "009a1f293253e41e",
                "amount": 2,
                "C_": "0224f1c4c564230ad3d96c5033efdc425582397a5a7691d600202732edc6d4b1ec"
            },
            {
                "id": "009a1f293253e41e",
                "amount": 8,
                "C_": "0277d1de806ed177007e5b94a8139343b6382e472c752a74e99949d511f7194f6c"
            }
        ]
    })json");

    auto resp = j.get<PostMintResponse>();
    REQUIRE(resp.signatures.size() == 2);
    CHECK(resp.signatures[0].amount == 2);
    CHECK(resp.signatures[1].amount == 8);
}

// ============================================================
// PostMeltQuoteBolt11 tests (NUT-05/NUT-23)
// ============================================================

TEST_CASE("PostMeltQuoteBolt11Request JSON roundtrip", "[api][nut05]") {
    PostMeltQuoteBolt11Request req("lnbc100n1p3kdrv5sp5...", "sat");

    nlohmann::json j = req;
    CHECK(j["request"] == "lnbc100n1p3kdrv5sp5...");
    CHECK(j["unit"] == "sat");

    auto req2 = j.get<PostMeltQuoteBolt11Request>();
    CHECK(req2.request == "lnbc100n1p3kdrv5sp5...");
    CHECK(req2.unit == "sat");
}

// NUT-23 spec example
TEST_CASE("PostMeltQuoteBolt11Response decode NUT-23 spec example", "[api][nut05]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "TRmjduhIsPxd...",
        "amount": 10,
        "fee_reserve": 2,
        "state": "UNPAID",
        "expiry": 1701704757
    })json");

    auto resp = j.get<PostMeltQuoteBolt11Response>();
    CHECK(resp.quote == "TRmjduhIsPxd...");
    CHECK(resp.amount == 10);
    CHECK(resp.fee_reserve == 2);
    CHECK(resp.state == "UNPAID");
    REQUIRE(resp.expiry.has_value());
    CHECK(resp.expiry.value() == 1701704757);
    CHECK_FALSE(resp.payment_preimage.has_value());
    CHECK_FALSE(resp.change.has_value());
}

TEST_CASE("PostMeltQuoteBolt11Response with payment preimage", "[api][nut05]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "TRmjduhIsPxd...",
        "amount": 10,
        "fee_reserve": 2,
        "state": "PAID",
        "expiry": 1701704757,
        "payment_preimage": "c5a1ae1f639e1f4a3872e81500fd028bece7bedc1152f740cba5c3417b748c1b"
    })json");

    auto resp = j.get<PostMeltQuoteBolt11Response>();
    CHECK(resp.state == "PAID");
    REQUIRE(resp.payment_preimage.has_value());
    CHECK(resp.payment_preimage.value() == "c5a1ae1f639e1f4a3872e81500fd028bece7bedc1152f740cba5c3417b748c1b");
}

TEST_CASE("PostMeltQuoteBolt11Response JSON roundtrip", "[api][nut05]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "test-melt",
        "amount": 100,
        "fee_reserve": 5,
        "state": "PAID",
        "expiry": 1640995200,
        "payment_preimage": "abc123"
    })json");

    auto resp = j.get<PostMeltQuoteBolt11Response>();
    nlohmann::json j2 = resp;
    auto resp2 = j2.get<PostMeltQuoteBolt11Response>();

    CHECK(resp2.quote == "test-melt");
    CHECK(resp2.amount == 100);
    CHECK(resp2.fee_reserve == 5);
    CHECK(resp2.state == "PAID");
    CHECK(resp2.payment_preimage.value() == "abc123");
}

// Mirrors DotNut NullExpiryTests_PostMeltQuoteBolt11Response
TEST_CASE("PostMeltQuoteBolt11Response with null expiry", "[api][nut05]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "melt-quote-id",
        "amount": 1000,
        "fee_reserve": 50,
        "state": "PAID",
        "expiry": null,
        "payment_preimage": "test-preimage"
    })json");

    auto resp = j.get<PostMeltQuoteBolt11Response>();
    CHECK(resp.quote == "melt-quote-id");
    CHECK_FALSE(resp.expiry.has_value());
    CHECK(resp.payment_preimage.value() == "test-preimage");
}

TEST_CASE("PostMeltQuoteBolt11Response with absent expiry", "[api][nut05]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "melt-quote-id",
        "amount": 1000,
        "fee_reserve": 50,
        "state": "UNPAID"
    })json");

    auto resp = j.get<PostMeltQuoteBolt11Response>();
    CHECK_FALSE(resp.expiry.has_value());
    CHECK_FALSE(resp.payment_preimage.has_value());
    CHECK_FALSE(resp.change.has_value());
}

TEST_CASE("PostMeltQuoteBolt11Response with NUT-08 change", "[api][nut05]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "q1",
        "amount": 10,
        "fee_reserve": 2,
        "state": "PAID",
        "expiry": 1701704757,
        "payment_preimage": "deadbeef",
        "change": [{
            "id": "009a1f293253e41e",
            "amount": 1,
            "C_": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
        }]
    })json");

    auto resp = j.get<PostMeltQuoteBolt11Response>();
    REQUIRE(resp.change.has_value());
    REQUIRE(resp.change.value().size() == 1);
    CHECK(resp.change.value()[0].amount == 1);
}

TEST_CASE("PostMeltQuoteBolt11Response serialization omits absent optionals", "[api][nut05]") {
    PostMeltQuoteBolt11Response resp;
    resp.quote = "q1";
    resp.amount = 10;
    resp.fee_reserve = 2;
    resp.state = "UNPAID";

    nlohmann::json j = resp;
    CHECK(j.contains("quote"));
    CHECK(j.contains("amount"));
    CHECK(j.contains("fee_reserve"));
    CHECK(j.contains("state"));
    CHECK_FALSE(j.contains("expiry"));
    CHECK_FALSE(j.contains("payment_preimage"));
    CHECK_FALSE(j.contains("change"));
}

// PostMeltBolt11Request
TEST_CASE("PostMeltBolt11Request JSON roundtrip", "[api][nut05]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "od4CN5smMMS3K3QVHkbGGNCTxfcAIyIXeq8IrfhP",
        "inputs": [{
            "amount": 10,
            "id": "009a1f293253e41e",
            "secret": "secret1",
            "C": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
        }]
    })json");

    auto req = j.get<PostMeltBolt11Request>();
    CHECK(req.quote == "od4CN5smMMS3K3QVHkbGGNCTxfcAIyIXeq8IrfhP");
    REQUIRE(req.inputs.size() == 1);
    CHECK(req.inputs[0].amount == 10);
    CHECK_FALSE(req.outputs.has_value());

    nlohmann::json j2 = req;
    CHECK_FALSE(j2.contains("outputs"));
}

TEST_CASE("PostMeltBolt11Request with NUT-08 change outputs", "[api][nut05]") {
    auto j = nlohmann::json::parse(R"json({
        "quote": "test-quote",
        "inputs": [{
            "amount": 12,
            "id": "009a1f293253e41e",
            "secret": "secret1",
            "C": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
        }],
        "outputs": [{
            "amount": 1,
            "id": "009a1f293253e41e",
            "B_": "03b0f36d6d47ce14df8a7be9137712c42bcdd960b19dd02f1d4a9703b1f31d7513"
        }]
    })json");

    auto req = j.get<PostMeltBolt11Request>();
    REQUIRE(req.outputs.has_value());
    REQUIRE(req.outputs.value().size() == 1);
    CHECK(req.outputs.value()[0].amount == 1);

    nlohmann::json j2 = req;
    REQUIRE(j2.contains("outputs"));
    CHECK(j2["outputs"].size() == 1);
}

// ============================================================
// GetInfoResponse tests (NUT-06)
// ============================================================

// NUT-06 spec example
static const char* NUT06_INFO_JSON = R"json({
    "name": "Bob's Cashu mint",
    "pubkey": "0283bf290884eed3a7ca2663fc0260de2e2064d6b355ea13f98dec004b7a7ead99",
    "version": "Nutshell/0.15.0",
    "description": "The short mint description",
    "description_long": "A description that can be a long piece of text.",
    "contact": [
        {"method": "email", "info": "contact@me.com"},
        {"method": "twitter", "info": "@me"}
    ],
    "motd": "Message to display to users.",
    "icon_url": "https://mint.host/icon.jpg",
    "urls": ["https://mint.host", "http://mint.onion"],
    "time": 1725304480,
    "tos_url": "https://mint.host/tos",
    "nuts": {
        "4": {
            "methods": [{"method": "bolt11", "unit": "sat", "min_amount": 0, "max_amount": 10000}],
            "disabled": false
        },
        "5": {
            "methods": [{"method": "bolt11", "unit": "sat", "min_amount": 100, "max_amount": 10000}],
            "disabled": false
        },
        "7": {"supported": true},
        "8": {"supported": true},
        "9": {"supported": true}
    }
})json";

TEST_CASE("GetInfoResponse decode NUT-06 spec example", "[api][nut06]") {
    auto j = nlohmann::json::parse(NUT06_INFO_JSON);
    auto info = j.get<GetInfoResponse>();

    REQUIRE(info.name.has_value());
    CHECK(info.name.value() == "Bob's Cashu mint");
    REQUIRE(info.pubkey.has_value());
    CHECK(info.pubkey.value() == "0283bf290884eed3a7ca2663fc0260de2e2064d6b355ea13f98dec004b7a7ead99");
    REQUIRE(info.version.has_value());
    CHECK(info.version.value() == "Nutshell/0.15.0");
    REQUIRE(info.description.has_value());
    CHECK(info.description.value() == "The short mint description");
    REQUIRE(info.description_long.has_value());
    REQUIRE(info.contact.has_value());
    CHECK(info.contact.value().size() == 2);
    CHECK(info.contact.value()[0].method == "email");
    CHECK(info.contact.value()[1].info == "@me");
    REQUIRE(info.motd.has_value());
    CHECK(info.motd.value() == "Message to display to users.");
    REQUIRE(info.icon_url.has_value());
    REQUIRE(info.urls.has_value());
    CHECK(info.urls.value().size() == 2);
    REQUIRE(info.time.has_value());
    CHECK(info.time.value() == 1725304480);
    REQUIRE(info.tos_url.has_value());
    REQUIRE(info.nuts.has_value());
    CHECK(info.nuts.value().size() == 5);
    CHECK(info.nuts.value().count("4") == 1);
    CHECK(info.nuts.value().count("7") == 1);
}

TEST_CASE("GetInfoResponse JSON roundtrip", "[api][nut06]") {
    auto j = nlohmann::json::parse(NUT06_INFO_JSON);
    auto info = j.get<GetInfoResponse>();

    nlohmann::json j2 = info;
    auto info2 = j2.get<GetInfoResponse>();

    CHECK(info2.name.value() == "Bob's Cashu mint");
    CHECK(info2.contact.value().size() == 2);
    CHECK(info2.nuts.value().size() == 5);
    CHECK(info2.time.value() == 1725304480);
}

TEST_CASE("GetInfoResponse minimal (all fields absent)", "[api][nut06]") {
    auto j = nlohmann::json::parse("{}");
    auto info = j.get<GetInfoResponse>();

    CHECK_FALSE(info.name.has_value());
    CHECK_FALSE(info.pubkey.has_value());
    CHECK_FALSE(info.version.has_value());
    CHECK_FALSE(info.description.has_value());
    CHECK_FALSE(info.contact.has_value());
    CHECK_FALSE(info.motd.has_value());
    CHECK_FALSE(info.nuts.has_value());
    CHECK_FALSE(info.time.has_value());
}

TEST_CASE("GetInfoResponse serialization omits absent optionals", "[api][nut06]") {
    GetInfoResponse info;
    info.name = "Test mint";

    nlohmann::json j = info;
    CHECK(j.contains("name"));
    CHECK_FALSE(j.contains("pubkey"));
    CHECK_FALSE(j.contains("version"));
    CHECK_FALSE(j.contains("description"));
    CHECK_FALSE(j.contains("contact"));
    CHECK_FALSE(j.contains("motd"));
    CHECK_FALSE(j.contains("nuts"));
    CHECK_FALSE(j.contains("time"));
    CHECK_FALSE(j.contains("urls"));
}

TEST_CASE("GetInfoResponse nuts field can be parsed for method settings", "[api][nut06]") {
    auto j = nlohmann::json::parse(NUT06_INFO_JSON);
    auto info = j.get<GetInfoResponse>();

    REQUIRE(info.nuts.has_value());
    auto& nut4 = info.nuts.value().at("4");
    auto methods = nut4["methods"].get<std::vector<MethodSetting>>();
    REQUIRE(methods.size() == 1);
    CHECK(methods[0].method == "bolt11");
    CHECK(methods[0].unit == "sat");
    REQUIRE(methods[0].min_amount.has_value());
    CHECK(methods[0].min_amount.value() == 0);
    REQUIRE(methods[0].max_amount.has_value());
    CHECK(methods[0].max_amount.value() == 10000);
}

TEST_CASE("ContactInfo JSON roundtrip", "[api][nut06]") {
    ContactInfo c("nostr", "npub1abc...");
    nlohmann::json j = c;
    CHECK(j["method"] == "nostr");
    CHECK(j["info"] == "npub1abc...");

    auto c2 = j.get<ContactInfo>();
    CHECK(c2.method == "nostr");
    CHECK(c2.info == "npub1abc...");
}

TEST_CASE("MethodSetting with optional fields absent", "[api][nut06]") {
    auto j = nlohmann::json::parse(R"json({"method": "bolt11", "unit": "sat"})json");
    auto s = j.get<MethodSetting>();

    CHECK(s.method == "bolt11");
    CHECK(s.unit == "sat");
    CHECK_FALSE(s.min_amount.has_value());
    CHECK_FALSE(s.max_amount.has_value());
    CHECK_FALSE(s.options.has_value());
}

TEST_CASE("MethodSetting serialization omits absent optionals", "[api][nut06]") {
    MethodSetting s("bolt11", "sat");
    nlohmann::json j = s;

    CHECK(j.contains("method"));
    CHECK(j.contains("unit"));
    CHECK_FALSE(j.contains("min_amount"));
    CHECK_FALSE(j.contains("max_amount"));
    CHECK_FALSE(j.contains("options"));
}

// ============================================================
// PostCheckState tests (NUT-07)
// ============================================================

// NUT-07 spec example
TEST_CASE("PostCheckStateRequest JSON roundtrip", "[api][nut07]") {
    PostCheckStateRequest req({"02599b9ea0a1ad4143706c2a5a4a568ce442dd4313e1cf1f7f0b58a317c1a355ee"});

    nlohmann::json j = req;
    REQUIRE(j["Ys"].size() == 1);
    CHECK(j["Ys"][0] == "02599b9ea0a1ad4143706c2a5a4a568ce442dd4313e1cf1f7f0b58a317c1a355ee");

    auto req2 = j.get<PostCheckStateRequest>();
    CHECK(req2.Ys.size() == 1);
}

TEST_CASE("PostCheckStateResponse decode NUT-07 spec example", "[api][nut07]") {
    auto j = nlohmann::json::parse(R"json({
        "states": [{
            "Y": "02599b9ea0a1ad4143706c2a5a4a568ce442dd4313e1cf1f7f0b58a317c1a355ee",
            "state": "SPENT",
            "witness": "{\"signatures\": [\"b2cf120a...\"]}"
        }]
    })json");

    auto resp = j.get<PostCheckStateResponse>();
    REQUIRE(resp.states.size() == 1);
    CHECK(resp.states[0].Y == "02599b9ea0a1ad4143706c2a5a4a568ce442dd4313e1cf1f7f0b58a317c1a355ee");
    CHECK(resp.states[0].state == "SPENT");
    REQUIRE(resp.states[0].witness.has_value());
}

TEST_CASE("StateResponseItem without witness", "[api][nut07]") {
    auto j = nlohmann::json::parse(R"json({
        "Y": "02abc...",
        "state": "UNSPENT"
    })json");

    auto item = j.get<StateResponseItem>();
    CHECK(item.state == "UNSPENT");
    CHECK_FALSE(item.witness.has_value());
}

TEST_CASE("StateResponseItem with null witness", "[api][nut07]") {
    auto j = nlohmann::json::parse(R"json({
        "Y": "02abc...",
        "state": "PENDING",
        "witness": null
    })json");

    auto item = j.get<StateResponseItem>();
    CHECK(item.state == "PENDING");
    CHECK_FALSE(item.witness.has_value());
}

TEST_CASE("StateResponseItem serialization omits absent witness", "[api][nut07]") {
    StateResponseItem item("02abc...", "UNSPENT");
    nlohmann::json j = item;

    CHECK(j.contains("Y"));
    CHECK(j.contains("state"));
    CHECK_FALSE(j.contains("witness"));
}

TEST_CASE("StateResponseItem rejects invalid state", "[api][nut07]") {
    auto j = nlohmann::json::parse(R"json({
        "Y": "02abc...",
        "state": "INVALID"
    })json");

    CHECK_THROWS_AS(j.get<StateResponseItem>(), std::invalid_argument);
}

TEST_CASE("PostCheckStateResponse multiple states", "[api][nut07]") {
    auto j = nlohmann::json::parse(R"json({
        "states": [
            {"Y": "02aaa...", "state": "UNSPENT"},
            {"Y": "02bbb...", "state": "SPENT"},
            {"Y": "02ccc...", "state": "PENDING"}
        ]
    })json");

    auto resp = j.get<PostCheckStateResponse>();
    REQUIRE(resp.states.size() == 3);
    CHECK(resp.states[0].state == "UNSPENT");
    CHECK(resp.states[1].state == "SPENT");
    CHECK(resp.states[2].state == "PENDING");
}

// ============================================================
// PostRestore tests (NUT-09)
// ============================================================

TEST_CASE("PostRestoreRequest JSON roundtrip", "[api][nut09]") {
    auto j = nlohmann::json::parse(R"json({
        "outputs": [{
            "amount": 1,
            "id": "009a1f293253e41e",
            "B_": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
        }]
    })json");

    auto req = j.get<PostRestoreRequest>();
    REQUIRE(req.outputs.size() == 1);
    CHECK(req.outputs[0].amount == 1);

    nlohmann::json j2 = req;
    CHECK(j2["outputs"].size() == 1);
}

TEST_CASE("PostRestoreResponse JSON roundtrip", "[api][nut09]") {
    auto j = nlohmann::json::parse(R"json({
        "outputs": [{
            "amount": 1,
            "id": "009a1f293253e41e",
            "B_": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
        }],
        "signatures": [{
            "id": "009a1f293253e41e",
            "amount": 1,
            "C_": "03b0f36d6d47ce14df8a7be9137712c42bcdd960b19dd02f1d4a9703b1f31d7513"
        }]
    })json");

    auto resp = j.get<PostRestoreResponse>();
    REQUIRE(resp.outputs.size() == 1);
    REQUIRE(resp.signatures.size() == 1);
    CHECK(resp.outputs[0].amount == 1);
    CHECK(resp.signatures[0].amount == 1);

    nlohmann::json j2 = resp;
    auto resp2 = j2.get<PostRestoreResponse>();
    CHECK(resp2.outputs.size() == 1);
    CHECK(resp2.signatures.size() == 1);
}

TEST_CASE("PostRestoreResponse rejects mismatched lengths", "[api][nut09]") {
    auto j = nlohmann::json::parse(R"json({
        "outputs": [
            {
                "amount": 1,
                "id": "009a1f293253e41e",
                "B_": "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
            },
            {
                "amount": 2,
                "id": "009a1f293253e41e",
                "B_": "03b0f36d6d47ce14df8a7be9137712c42bcdd960b19dd02f1d4a9703b1f31d7513"
            }
        ],
        "signatures": [{
            "id": "009a1f293253e41e",
            "amount": 1,
            "C_": "03b0f36d6d47ce14df8a7be9137712c42bcdd960b19dd02f1d4a9703b1f31d7513"
        }]
    })json");

    CHECK_THROWS_AS(j.get<PostRestoreResponse>(), std::invalid_argument);
}
