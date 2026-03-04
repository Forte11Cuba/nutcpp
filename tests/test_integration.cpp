#include <catch2/catch_test_macros.hpp>
#include <algorithm>
#include "nutcpp/api/cashu_http_client.h"
#include "nutcpp/api_models/mint_models.h"
#include "nutcpp/api_models/melt_models.h"

using namespace nutcpp;
using namespace nutcpp::api;

static const std::string TESTNUT_URL = "https://testnut.cashu.space";

// ======================================================================
// Integration tests — require internet connection.
// Run: ./build/tests/nutcpp_tests [integration]
// Skip: ./build/tests/nutcpp_tests ~[integration]
// ======================================================================

TEST_CASE("GET /v1/info from testnut", "[integration]") {
    CashuHttpClient client(TESTNUT_URL);
    auto info = client.get_info();

    // Mint should report a name.
    REQUIRE(info.name.has_value());
    CHECK(!info.name.value().empty());

    // Version string present.
    CHECK(info.version.has_value());

    // nuts map should exist and contain at least NUT-04 and NUT-05.
    REQUIRE(info.nuts.has_value());
    CHECK(info.nuts.value().count("4") > 0);
    CHECK(info.nuts.value().count("5") > 0);
}

TEST_CASE("GET /v1/keys from testnut", "[integration]") {
    CashuHttpClient client(TESTNUT_URL);
    auto keys_response = client.get_keys();

    // At least one active keyset.
    REQUIRE(!keys_response.keysets.empty());

    auto& first = keys_response.keysets[0];
    CHECK(!first.unit.empty());
    // Keys map should have entries.
    CHECK(first.keys.size() > 0);
}

TEST_CASE("GET /v1/keysets from testnut", "[integration]") {
    CashuHttpClient client(TESTNUT_URL);
    auto keysets_response = client.get_keysets();

    REQUIRE(!keysets_response.keysets.empty());

    // At least one active keyset with unit "sat".
    bool found_active_sat = false;
    for (auto& ks : keysets_response.keysets) {
        if (ks.active && ks.unit == "sat") {
            found_active_sat = true;
            break;
        }
    }
    CHECK(found_active_sat);
}

TEST_CASE("GET /v1/keys/{id} from testnut", "[integration]") {
    CashuHttpClient client(TESTNUT_URL);

    // First get a keyset ID from /v1/keysets.
    auto keysets_response = client.get_keysets();
    REQUIRE(!keysets_response.keysets.empty());

    auto& target_id = keysets_response.keysets[0].id;

    // Request keys for that specific keyset.
    auto keys_response = client.get_keys(target_id);
    REQUIRE(!keys_response.keysets.empty());

    // Find the keyset matching our target ID (response order not guaranteed).
    auto it = std::find_if(keys_response.keysets.begin(), keys_response.keysets.end(),
        [&](const auto& ks) { return ks.id == target_id; });
    REQUIRE(it != keys_response.keysets.end());
    CHECK(!it->keys.empty());
}

TEST_CASE("POST /v1/mint/quote/bolt11 from testnut", "[integration]") {
    CashuHttpClient client(TESTNUT_URL);

    auto response = client.create_mint_quote<PostMintQuoteBolt11Request,
                                             PostMintQuoteBolt11Response>(
        "bolt11", PostMintQuoteBolt11Request(1, "sat"));

    // Quote ID should be non-empty.
    CHECK(!response.quote.empty());
    // Request should be a Lightning invoice (starts with "ln").
    CHECK(response.request.substr(0, 2) == "ln");
    // State should be present.
    CHECK(!response.state.empty());
}

TEST_CASE("POST /v1/melt/quote/bolt11 from testnut", "[integration]") {
    CashuHttpClient client(TESTNUT_URL);

    // First get a mint quote to obtain a valid LN invoice.
    auto mint_quote = client.create_mint_quote<PostMintQuoteBolt11Request,
                                               PostMintQuoteBolt11Response>(
        "bolt11", PostMintQuoteBolt11Request(1, "sat"));

    // Use that invoice to create a melt quote.
    auto response = client.create_melt_quote<PostMeltQuoteBolt11Request,
                                             PostMeltQuoteBolt11Response>(
        "bolt11", PostMeltQuoteBolt11Request(mint_quote.request, "sat"));

    // Quote should have an ID.
    CHECK(!response.quote.empty());
    // Amount should be > 0.
    CHECK(response.amount > 0);
    // State should be present.
    CHECK(!response.state.empty());
}
