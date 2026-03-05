#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include "nutcpp/payment/nut10_locking_condition.h"
#include "nutcpp/payment/payment_request_transport.h"
#include "nutcpp/payment/payment_request.h"
#include "nutcpp/payment/payment_request_payload.h"

using namespace nutcpp;
using namespace nutcpp::payment;
using json = nlohmann::json;

// ====== Nut10LockingCondition ======

TEST_CASE("Nut10LockingCondition JSON roundtrip with tags", "[payment]") {
    Nut10LockingCondition c;
    c.kind = "P2PK";
    c.data = "02abc123";
    c.tags = std::vector<Tag>{Tag("timeout", {"3600"})};

    json j = c;
    REQUIRE(j["k"] == "P2PK");
    REQUIRE(j["d"] == "02abc123");
    REQUIRE(j["t"].size() == 1);
    REQUIRE(j["t"][0][0] == "timeout");
    REQUIRE(j["t"][0][1] == "3600");

    auto c2 = j.get<Nut10LockingCondition>();
    REQUIRE(c2.kind == "P2PK");
    REQUIRE(c2.data == "02abc123");
    REQUIRE(c2.tags.has_value());
    REQUIRE(c2.tags->size() == 1);
    REQUIRE(c2.tags->at(0).key == "timeout");
    REQUIRE(c2.tags->at(0).values[0] == "3600");
}

TEST_CASE("Nut10LockingCondition JSON without tags", "[payment]") {
    Nut10LockingCondition c("HTLC", "deadbeef");
    json j = c;

    REQUIRE(j["k"] == "HTLC");
    REQUIRE(j["d"] == "deadbeef");
    REQUIRE_FALSE(j.contains("t"));

    auto c2 = j.get<Nut10LockingCondition>();
    REQUIRE(c2.kind == "HTLC");
    REQUIRE(c2.data == "deadbeef");
    REQUIRE_FALSE(c2.tags.has_value());
}

TEST_CASE("Nut10LockingCondition JSON with empty tags", "[payment]") {
    Nut10LockingCondition c("P2PK", "02abc123", std::vector<Tag>{});
    json j = c;

    REQUIRE(j.contains("t"));
    REQUIRE(j["t"].is_array());
    REQUIRE(j["t"].empty());

    auto c2 = j.get<Nut10LockingCondition>();
    REQUIRE(c2.tags.has_value());
    REQUIRE(c2.tags->empty());
}

// ====== PaymentRequestTransport ======

TEST_CASE("PaymentRequestTransport JSON roundtrip with tags", "[payment]") {
    PaymentRequestTransport t("nostr", "nprofile1abc", std::vector<Tag>{Tag("n", {"17"})});
    json j = t;

    REQUIRE(j["t"] == "nostr");
    REQUIRE(j["a"] == "nprofile1abc");
    REQUIRE(j["g"].size() == 1);
    REQUIRE(j["g"][0][0] == "n");
    REQUIRE(j["g"][0][1] == "17");

    auto t2 = j.get<PaymentRequestTransport>();
    REQUIRE(t2.type == "nostr");
    REQUIRE(t2.target == "nprofile1abc");
    REQUIRE(t2.tags.has_value());
    REQUIRE(t2.tags->at(0).key == "n");
    REQUIRE(t2.tags->at(0).values[0] == "17");
}

TEST_CASE("PaymentRequestTransport JSON without tags", "[payment]") {
    PaymentRequestTransport t("post", "https://example.com/pay");
    json j = t;

    REQUIRE(j["t"] == "post");
    REQUIRE(j["a"] == "https://example.com/pay");
    REQUIRE_FALSE(j.contains("g"));

    auto t2 = j.get<PaymentRequestTransport>();
    REQUIRE(t2.type == "post");
    REQUIRE(t2.target == "https://example.com/pay");
    REQUIRE_FALSE(t2.tags.has_value());
}

// ====== PaymentRequest ======

TEST_CASE("PaymentRequest JSON roundtrip all fields", "[payment]") {
    PaymentRequest r;
    r.payment_id = "b7a90176";
    r.amount = 10;
    r.unit = "sat";
    r.single_use = true;
    r.mints = std::vector<std::string>{"https://mint.example.com"};
    r.description = "Coffee payment";
    r.transports = {PaymentRequestTransport("nostr", "nprofile1abc", std::vector<Tag>{Tag("n", {"17"})})};
    r.nut10 = Nut10LockingCondition("P2PK", "02abc123");

    json j = r;
    REQUIRE(j["i"] == "b7a90176");
    REQUIRE(j["a"] == 10);
    REQUIRE(j["u"] == "sat");
    REQUIRE(j["s"] == true);
    REQUIRE(j["m"].size() == 1);
    REQUIRE(j["m"][0] == "https://mint.example.com");
    REQUIRE(j["d"] == "Coffee payment");
    REQUIRE(j["t"].size() == 1);
    REQUIRE(j["nut10"]["k"] == "P2PK");

    auto r2 = j.get<PaymentRequest>();
    REQUIRE(r2.payment_id.value() == "b7a90176");
    REQUIRE(r2.amount.value() == 10);
    REQUIRE(r2.unit.value() == "sat");
    REQUIRE(r2.single_use.value() == true);
    REQUIRE(r2.mints->size() == 1);
    REQUIRE(r2.mints->at(0) == "https://mint.example.com");
    REQUIRE(r2.description.value() == "Coffee payment");
    REQUIRE(r2.transports.size() == 1);
    REQUIRE(r2.transports[0].type == "nostr");
    REQUIRE(r2.nut10.has_value());
    REQUIRE(r2.nut10->kind == "P2PK");
}

TEST_CASE("PaymentRequest JSON minimal (empty)", "[payment]") {
    PaymentRequest r;
    json j = r;

    REQUIRE_FALSE(j.contains("i"));
    REQUIRE_FALSE(j.contains("a"));
    REQUIRE_FALSE(j.contains("u"));
    REQUIRE_FALSE(j.contains("s"));
    REQUIRE_FALSE(j.contains("m"));
    REQUIRE_FALSE(j.contains("d"));
    REQUIRE(j.contains("t"));
    REQUIRE(j["t"].is_array());
    REQUIRE(j["t"].empty());
    REQUIRE_FALSE(j.contains("nut10"));

    auto r2 = j.get<PaymentRequest>();
    REQUIRE_FALSE(r2.payment_id.has_value());
    REQUIRE_FALSE(r2.amount.has_value());
    REQUIRE_FALSE(r2.unit.has_value());
    REQUIRE_FALSE(r2.single_use.has_value());
    REQUIRE_FALSE(r2.mints.has_value());
    REQUIRE_FALSE(r2.description.has_value());
    REQUIRE(r2.transports.empty());
    REQUIRE_FALSE(r2.nut10.has_value());
}

TEST_CASE("PaymentRequest NUT-18 spec example JSON structure", "[payment]") {
    // The JSON from the NUT-18 spec example (without encoding)
    auto j = json::parse(R"({
        "i": "b7a90176",
        "a": 10,
        "u": "sat",
        "m": ["https://nofees.testnut.cashu.space"],
        "t": [
            {
                "t": "nostr",
                "a": "nprofile1qy28wumn8ghj7un9d3shjtnyv9kh2uewd9hsz9mhwden5te0wfjkccte9curxven9eehqctrv5hszrthwden5te0dehhxtnvdakqqgydaqy7curk439ykptkysv7udhdhu68sucm295akqefdehkf0d495cwunl5",
                "g": [["n", "17"]]
            }
        ]
    })");

    auto r = j.get<PaymentRequest>();
    REQUIRE(r.payment_id.value() == "b7a90176");
    REQUIRE(r.amount.value() == 10);
    REQUIRE(r.unit.value() == "sat");
    REQUIRE(r.mints->size() == 1);
    REQUIRE(r.mints->at(0) == "https://nofees.testnut.cashu.space");
    REQUIRE(r.transports.size() == 1);
    REQUIRE(r.transports[0].type == "nostr");
    REQUIRE(r.transports[0].target == "nprofile1qy28wumn8ghj7un9d3shjtnyv9kh2uewd9hsz9mhwden5te0wfjkccte9curxven9eehqctrv5hszrthwden5te0dehhxtnvdakqqgydaqy7curk439ykptkysv7udhdhu68sucm295akqefdehkf0d495cwunl5");
    REQUIRE(r.transports[0].tags.has_value());
    REQUIRE(r.transports[0].tags->size() == 1);
    REQUIRE(r.transports[0].tags->at(0).key == "n");
    REQUIRE(r.transports[0].tags->at(0).values[0] == "17");
    REQUIRE_FALSE(r.single_use.has_value());
    REQUIRE_FALSE(r.description.has_value());
    REQUIRE_FALSE(r.nut10.has_value());
}

TEST_CASE("PaymentRequest with nut10 locking condition", "[payment]") {
    PaymentRequest r;
    r.payment_id = "c9e45d2a";
    r.amount = 500;
    r.unit = "sat";
    r.mints = std::vector<std::string>{"https://mint.example.com"};
    r.nut10 = Nut10LockingCondition(
        "P2PK",
        "02c3b5bb27e361457c92d93d78dd73d3d53732110b2cfe8b50fbc0abc615e9c331",
        std::vector<Tag>{Tag("timeout", {"3600"})}
    );

    json j = r;
    REQUIRE(j["nut10"]["k"] == "P2PK");
    REQUIRE(j["nut10"]["d"] == "02c3b5bb27e361457c92d93d78dd73d3d53732110b2cfe8b50fbc0abc615e9c331");
    REQUIRE(j["nut10"]["t"][0][0] == "timeout");
    REQUIRE(j["nut10"]["t"][0][1] == "3600");

    auto r2 = j.get<PaymentRequest>();
    REQUIRE(r2.nut10.has_value());
    REQUIRE(r2.nut10->kind == "P2PK");
    REQUIRE(r2.nut10->data == "02c3b5bb27e361457c92d93d78dd73d3d53732110b2cfe8b50fbc0abc615e9c331");
    REQUIRE(r2.nut10->tags->at(0).key == "timeout");
}

// ====== PaymentRequestPayload ======

TEST_CASE("PaymentRequestPayload JSON roundtrip all fields", "[payment]") {
    PubKey C("02c3b5bb27e361457c92d93d78dd73d3d53732110b2cfe8b50fbc0abc615e9c331");
    KeysetId kid("00ad268c4d1f5826");
    Proof proof(1, kid, "secret123", C);

    PaymentRequestPayload p("https://mint.example.com", "sat", {proof}, "pay123", "thanks");
    json j = p;

    REQUIRE(j["id"] == "pay123");
    REQUIRE(j["memo"] == "thanks");
    REQUIRE(j["mint"] == "https://mint.example.com");
    REQUIRE(j["unit"] == "sat");
    REQUIRE(j["proofs"].size() == 1);
    REQUIRE(j["proofs"][0]["amount"] == 1);
    REQUIRE(j["proofs"][0]["secret"] == "secret123");

    auto p2 = j.get<PaymentRequestPayload>();
    REQUIRE(p2.id.value() == "pay123");
    REQUIRE(p2.memo.value() == "thanks");
    REQUIRE(p2.mint == "https://mint.example.com");
    REQUIRE(p2.unit == "sat");
    REQUIRE(p2.proofs.size() == 1);
    REQUIRE(p2.proofs[0].amount == 1);
}

TEST_CASE("PaymentRequestPayload JSON without optionals", "[payment]") {
    PubKey C("02c3b5bb27e361457c92d93d78dd73d3d53732110b2cfe8b50fbc0abc615e9c331");
    KeysetId kid("00ad268c4d1f5826");
    Proof proof(1, kid, "secret123", C);

    PaymentRequestPayload p("https://mint.example.com", "sat", {proof});
    json j = p;

    REQUIRE_FALSE(j.contains("id"));
    REQUIRE_FALSE(j.contains("memo"));
    REQUIRE(j["mint"] == "https://mint.example.com");
    REQUIRE(j["unit"] == "sat");
    REQUIRE(j["proofs"].size() == 1);

    auto p2 = j.get<PaymentRequestPayload>();
    REQUIRE_FALSE(p2.id.has_value());
    REQUIRE_FALSE(p2.memo.has_value());
}

TEST_CASE("PaymentRequest multiple transports", "[payment]") {
    PaymentRequest r;
    r.amount = 500;
    r.unit = "sat";
    r.transports = {
        PaymentRequestTransport("nostr", "nprofile1abc", std::vector<Tag>{Tag("n", {"17"})}),
        PaymentRequestTransport("post", "https://api.example.com/pay"),
    };

    json j = r;
    REQUIRE(j["t"].size() == 2);
    REQUIRE(j["t"][0]["t"] == "nostr");
    REQUIRE(j["t"][1]["t"] == "post");

    auto r2 = j.get<PaymentRequest>();
    REQUIRE(r2.transports.size() == 2);
    REQUIRE(r2.transports[0].type == "nostr");
    REQUIRE(r2.transports[0].tags.has_value());
    REQUIRE(r2.transports[1].type == "post");
    REQUIRE_FALSE(r2.transports[1].tags.has_value());
}
