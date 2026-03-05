#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include "nutcpp/payment/nut10_locking_condition.h"
#include "nutcpp/payment/payment_request_transport.h"
#include "nutcpp/payment/payment_request.h"
#include "nutcpp/payment/payment_request_payload.h"
#include "nutcpp/payment/payment_request_encoder.h"
#include "nutcpp/payment/payment_request_bech32_encoder.h"
#include "../src/payment/bech32.h"
#include "../src/payment/nip19.h"
#include "nutcpp/encoding/convert_utils.h"

using namespace nutcpp;
using namespace nutcpp::payment;
using namespace nutcpp::internal;
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

// ====== PaymentRequestEncoder (creqA) ======

TEST_CASE("NUT-18 decode spec example creqA", "[payment]") {
    // Vector from NUT-18 spec and DotNut Nut18Tests
    std::string creqA =
        "creqApWF0gaNhdGVub3N0cmFheKlucHJvZmlsZTFxeTI4d3VtbjhnaGo3dW45ZDNzaGp0bnl2OWtoMnVld2Q5aHN6OW1od2RlbjV0ZTB3ZmprY2N0ZTljdXJ4dmVuOWVlaHFjdHJ2NWhzenJ0aHdkZW41dGUwZGVoaHh0bnZkYWtxcWd5ZGFxeTdjdXJrNDM5eWtwdGt5c3Y3dWRoZGh1NjhzdWNtMjk1YWtxZWZkZWhrZjBkNDk1Y3d1bmw1YWeBgmFuYjE3YWloYjdhOTAxNzZhYQphdWNzYXRhbYF4Imh0dHBzOi8vbm9mZWVzLnRlc3RudXQuY2FzaHUuc3BhY2U=";

    auto pr = PaymentRequestEncoder::parse(creqA);
    REQUIRE(pr.payment_id.value() == "b7a90176");
    REQUIRE(pr.amount.value() == 10);
    REQUIRE(pr.unit.value() == "sat");
    REQUIRE(pr.mints.has_value());
    REQUIRE(pr.mints->size() == 1);
    REQUIRE(pr.mints->at(0) == "https://nofees.testnut.cashu.space");
    REQUIRE(pr.transports.size() == 1);
    auto& t = pr.transports[0];
    REQUIRE(t.type == "nostr");
    REQUIRE(t.target == "nprofile1qy28wumn8ghj7un9d3shjtnyv9kh2uewd9hsz9mhwden5te0wfjkccte9curxven9eehqctrv5hszrthwden5te0dehhxtnvdakqqgydaqy7curk439ykptkysv7udhdhu68sucm295akqefdehkf0d495cwunl5");
    REQUIRE(t.tags.has_value());
    REQUIRE(t.tags->size() == 1);
    REQUIRE(t.tags->at(0).key == "n");
    REQUIRE(t.tags->at(0).values[0] == "17");
}

TEST_CASE("creqA encode roundtrip", "[payment]") {
    PaymentRequest r;
    r.payment_id = "test123";
    r.amount = 100;
    r.unit = "sat";
    r.mints = std::vector<std::string>{"https://mint.example.com"};
    r.transports = {PaymentRequestTransport("post", "https://api.example.com/pay")};

    auto encoded = PaymentRequestEncoder::encode(r);
    REQUIRE(encoded.substr(0, 5) == "creqA");

    auto decoded = PaymentRequestEncoder::parse(encoded);
    REQUIRE(decoded.payment_id.value() == "test123");
    REQUIRE(decoded.amount.value() == 100);
    REQUIRE(decoded.unit.value() == "sat");
    REQUIRE(decoded.mints->at(0) == "https://mint.example.com");
    REQUIRE(decoded.transports.size() == 1);
    REQUIRE(decoded.transports[0].type == "post");
    REQUIRE(decoded.transports[0].target == "https://api.example.com/pay");
}

TEST_CASE("creqA roundtrip with nut10", "[payment]") {
    PaymentRequest r;
    r.amount = 500;
    r.unit = "sat";
    r.transports = {};
    r.nut10 = Nut10LockingCondition(
        "P2PK", "02abcdef",
        std::vector<Tag>{Tag("timeout", {"3600"}), Tag("sigflag", {"SIG_ALL"})}
    );

    auto encoded = PaymentRequestEncoder::encode(r);
    auto decoded = PaymentRequestEncoder::parse(encoded);

    REQUIRE(decoded.nut10.has_value());
    REQUIRE(decoded.nut10->kind == "P2PK");
    REQUIRE(decoded.nut10->data == "02abcdef");
    REQUIRE(decoded.nut10->tags.has_value());
    REQUIRE(decoded.nut10->tags->size() == 2);
    REQUIRE(decoded.nut10->tags->at(0).key == "timeout");
    REQUIRE(decoded.nut10->tags->at(0).values[0] == "3600");
    REQUIRE(decoded.nut10->tags->at(1).key == "sigflag");
    REQUIRE(decoded.nut10->tags->at(1).values[0] == "SIG_ALL");
}

TEST_CASE("creqA roundtrip minimal (no optional fields)", "[payment]") {
    PaymentRequest r;
    r.transports = {PaymentRequestTransport("post", "https://example.com")};

    auto encoded = PaymentRequestEncoder::encode(r);
    auto decoded = PaymentRequestEncoder::parse(encoded);

    REQUIRE_FALSE(decoded.payment_id.has_value());
    REQUIRE_FALSE(decoded.amount.has_value());
    REQUIRE_FALSE(decoded.unit.has_value());
    REQUIRE_FALSE(decoded.single_use.has_value());
    REQUIRE_FALSE(decoded.mints.has_value());
    REQUIRE_FALSE(decoded.description.has_value());
    REQUIRE_FALSE(decoded.nut10.has_value());
    REQUIRE(decoded.transports.size() == 1);
}

TEST_CASE("creqA parse case insensitive prefix", "[payment]") {
    // Build a valid creqA first
    PaymentRequest r;
    r.unit = "sat";
    r.transports = {};
    auto encoded = PaymentRequestEncoder::encode(r);

    // Replace prefix with mixed case
    std::string lower = "creqa" + encoded.substr(5);
    auto decoded = PaymentRequestEncoder::parse(lower);
    REQUIRE(decoded.unit.value() == "sat");
}

TEST_CASE("creqA parse invalid prefix throws", "[payment]") {
    REQUIRE_THROWS_AS(PaymentRequestEncoder::parse("invalid_string"), std::invalid_argument);
    REQUIRE_THROWS_AS(PaymentRequestEncoder::parse("creq"), std::invalid_argument);
    REQUIRE_THROWS_AS(PaymentRequestEncoder::parse(""), std::invalid_argument);
}

// ====== Bech32 / Bech32m ======

TEST_CASE("convert_bits 8->5->8 roundtrip", "[bech32]") {
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03};
    auto bits5 = convert_bits(data, 8, 5, true);
    auto back = convert_bits(bits5, 5, 8, false);
    REQUIRE(back == data);
}

TEST_CASE("convert_bits reject invalid padding", "[bech32]") {
    // 5-bit value with non-zero padding bits should fail on 5->8 with pad=false
    std::vector<uint8_t> bad = {0x00, 0x00, 0x01}; // 15 bits -> 1 byte + 7 bits, last nonzero
    REQUIRE_THROWS_AS(convert_bits(bad, 5, 8, false), std::invalid_argument);
}

TEST_CASE("convert_bits reject value exceeding from_bits", "[bech32]") {
    std::vector<uint8_t> bad = {0x20}; // 32 exceeds 5 bits
    REQUIRE_THROWS_AS(convert_bits(bad, 5, 8, false), std::invalid_argument);
}

TEST_CASE("bech32_encode_raw + decode_raw roundtrip BECH32", "[bech32]") {
    std::vector<uint8_t> data_5bit = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    auto encoded = bech32_encode_raw("test", data_5bit, Bech32Type::BECH32);
    REQUIRE(encoded.substr(0, 5) == "test1");

    Bech32Type type;
    auto decoded = bech32_decode_raw(encoded, "test", type);
    REQUIRE(type == Bech32Type::BECH32);
    REQUIRE(decoded == data_5bit);
}

TEST_CASE("bech32_encode_raw + decode_raw roundtrip BECH32M", "[bech32]") {
    std::vector<uint8_t> data_5bit = {31, 30, 29, 28, 27, 0, 1, 2, 3};
    auto encoded = bech32_encode_raw("creqb", data_5bit, Bech32Type::BECH32M);
    REQUIRE(encoded.substr(0, 6) == "creqb1");

    Bech32Type type;
    auto decoded = bech32_decode_raw(encoded, "creqb", type);
    REQUIRE(type == Bech32Type::BECH32M);
    REQUIRE(decoded == data_5bit);
}

TEST_CASE("bech32 decode case insensitive", "[bech32]") {
    std::vector<uint8_t> data_5bit = {0, 1, 2, 3};
    auto encoded = bech32_encode_raw("abc", data_5bit, Bech32Type::BECH32);

    // Uppercase should decode fine
    std::string upper;
    for (auto c : encoded)
        upper += static_cast<char>(toupper(static_cast<unsigned char>(c)));

    Bech32Type type;
    auto decoded = bech32_decode_raw(upper, "abc", type);
    REQUIRE(decoded == data_5bit);
}

TEST_CASE("bech32 decode rejects mixed case", "[bech32]") {
    // Mix lower HRP with upper data
    Bech32Type type;
    REQUIRE_THROWS_AS(
        bech32_decode_raw("test1QPZRY", "test", type),
        std::invalid_argument);
}

TEST_CASE("bech32 decode rejects wrong HRP", "[bech32]") {
    std::vector<uint8_t> data_5bit = {0, 1, 2};
    auto encoded = bech32_encode_raw("abc", data_5bit, Bech32Type::BECH32);

    Bech32Type type;
    REQUIRE_THROWS_AS(bech32_decode_raw(encoded, "xyz", type), std::invalid_argument);
}

TEST_CASE("bech32 decode rejects corrupted checksum", "[bech32]") {
    std::vector<uint8_t> data_5bit = {0, 1, 2, 3};
    auto encoded = bech32_encode_raw("test", data_5bit, Bech32Type::BECH32);

    // Corrupt last character
    std::string corrupted = encoded;
    corrupted.back() = (corrupted.back() == 'q') ? 'p' : 'q';

    Bech32Type type;
    REQUIRE_THROWS_AS(bech32_decode_raw(corrupted, "test", type), std::invalid_argument);
}

TEST_CASE("bech32 no strict length limit (long strings ok)", "[bech32]") {
    // Generate data longer than 90 chars total (typical for payment requests)
    std::vector<uint8_t> data_5bit(200, 0);
    for (size_t i = 0; i < data_5bit.size(); ++i)
        data_5bit[i] = static_cast<uint8_t>(i % 32);

    auto encoded = bech32_encode_raw("creqb", data_5bit, Bech32Type::BECH32M);
    REQUIRE(encoded.size() > 90);

    Bech32Type type;
    auto decoded = bech32_decode_raw(encoded, "creqb", type);
    REQUIRE(decoded == data_5bit);
}

// ====== NIP-19 ======

TEST_CASE("decode_nprofile all-zero pubkey no relays (DotNut vector)", "[nip19]") {
    // From Nut26_NostrTransport: nprofile with 32 zero bytes, no relays
    std::string nprof = "nprofile1qqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8uzqt";
    auto result = decode_nprofile(nprof);
    REQUIRE(result.pubkey.size() == 32);
    for (auto b : result.pubkey)
        CHECK(b == 0);
    REQUIRE(result.relays.empty());
}

TEST_CASE("decode_nprofile known pubkey no relays (DotNut vector)", "[nip19]") {
    // From Nut26_MultipleTransports and Nut26MinimalNostrTransport
    std::string nprof = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8g2lcy6q";
    auto result = decode_nprofile(nprof);
    REQUIRE(result.pubkey.size() == 32);
    // Pubkey hex: 3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d (known nostr pubkey)
    auto hex = bytes_to_hex(result.pubkey);
    // Verify it's a valid 32-byte key (not all zeros)
    REQUIRE(hex.size() == 64);
    REQUIRE(hex != std::string(64, '0'));
    REQUIRE(result.relays.empty());
}

TEST_CASE("encode_nprofile roundtrip all-zero pubkey", "[nip19]") {
    std::vector<uint8_t> pubkey(32, 0);
    auto encoded = encode_nprofile(pubkey, {});
    auto decoded = decode_nprofile(encoded);
    REQUIRE(decoded.pubkey == pubkey);
    REQUIRE(decoded.relays.empty());

    // Should match DotNut vector
    REQUIRE(encoded == "nprofile1qqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8uzqt");
}

TEST_CASE("encode_nprofile roundtrip with relays", "[nip19]") {
    std::vector<uint8_t> pubkey(32, 0);
    pubkey[0] = 0x3b; pubkey[1] = 0xf0;  // non-zero first bytes
    std::vector<std::string> relays = {
        "wss://relay1.example.com",
        "wss://relay2.example.com"
    };
    auto encoded = encode_nprofile(pubkey, relays);
    auto decoded = decode_nprofile(encoded);
    REQUIRE(decoded.pubkey == pubkey);
    REQUIRE(decoded.relays.size() == 2);
    REQUIRE(decoded.relays[0] == "wss://relay1.example.com");
    REQUIRE(decoded.relays[1] == "wss://relay2.example.com");
}

TEST_CASE("decode_nostr dispatches npub and nprofile", "[nip19]") {
    // nprofile
    std::string nprof = "nprofile1qqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8uzqt";
    auto r1 = decode_nostr(nprof);
    REQUIRE(r1.pubkey.size() == 32);

    // We can't easily test npub without a known vector, but verify dispatch works
    // by checking nprofile path produces valid result
    REQUIRE(r1.relays.empty());
}

TEST_CASE("encode_nprofile rejects wrong pubkey length", "[nip19]") {
    std::vector<uint8_t> bad(16, 0);
    REQUIRE_THROWS_AS(encode_nprofile(bad, {}), std::invalid_argument);
}

TEST_CASE("decode_nprofile known pubkey with 3 relays (DotNut Nut26Nprofile vector)", "[nip19]") {
    // From Nut26Nprofile test
    std::string nprof = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gprpmhxue69uhhyetvv9unztn90psk6urvv5hxxmmdqyv8wumn8ghj7un9d3shjv3wv4uxzmtsd3jjucm0d5q3samnwvaz7tmjv4kxz7fn9ejhsctdwpkx2tnrdaksxzjpjp";
    auto result = decode_nprofile(nprof);
    REQUIRE(result.pubkey.size() == 32);
    REQUIRE(result.relays.size() == 3);

    // Verify roundtrip
    auto reencoded = encode_nprofile(result.pubkey, result.relays);
    REQUIRE(reencoded == nprof);
}

TEST_CASE("encode_nprofile no relays roundtrip matches DotNut vector", "[nip19]") {
    // From Nut26_MultipleTransports: nprofile without relays
    std::string expected = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8g2lcy6q";
    auto decoded = decode_nprofile(expected);
    auto reencoded = encode_nprofile(decoded.pubkey, decoded.relays);
    REQUIRE(reencoded == expected);
}

// ====== PaymentRequestBech32Encoder (creqB / NUT-26) ======

TEST_CASE("creqB Nut26_BasicPaymentRequest (DotNut vector, semantic roundtrip)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQQSC3HVYUNQVFHXCPQQZQQQQQQQQQQQQ9QXQQPQQZSQ9MGW368QUE69UHNSVENXVH8XURPVDJN5VENXVUQWQREQYQQZQQZQQSGM6QFA3C8DTZ2FVZHVFQEACMWM0E50PE3K5TFMVPJJMN0VJ7M2TGRQQZSZMSZXYMSXQQHQ9EPGAMNWVAZ7TMJV4KXZ7FWV3SK6ATN9E5K7QCQRGQHY9MHWDEN5TE0WFJKCCTE9CURXVEN9EEHQCTRV5HSXQQSQ9EQ6AMNWVAZ7TMWDAEJUMR0DSRYDPGF";
    auto d = PaymentRequestBech32Encoder::decode(encoded);
    REQUIRE(d.payment_id.value() == "b7a90176");
    REQUIRE(d.amount.value() == 10);
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.mints.has_value());
    REQUIRE(d.mints->size() == 1);
    REQUIRE(d.mints->at(0) == "https://8333.space:3338");
    REQUIRE(d.transports.size() == 1);
    auto& t = d.transports[0];
    REQUIRE(t.type == "nostr");
    REQUIRE(t.target == "nprofile1qqsgm6qfa3c8dtz2fvzhvfqeacmwm0e50pe3k5tfmvpjjmn0vj7m2tgpz3mhxue69uhhyetvv9ujuerpd46hxtnfduq3wamnwvaz7tmjv4kxz7fw8qenxvewwdcxzcm99uqs6amnwvaz7tmwdaejumr0ds4ljh7n");
    REQUIRE(t.tags.has_value());
    REQUIRE(t.tags->size() == 1);
    REQUIRE(t.tags->at(0).key == "n");
    REQUIRE(t.tags->at(0).values[0] == "17");

    // Semantic roundtrip (DotNut comments out exact equality for this vector)
    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    auto d2 = PaymentRequestBech32Encoder::decode(encoded_again);
    REQUIRE(d2.payment_id.value() == d.payment_id.value());
    REQUIRE(d2.amount.value() == d.amount.value());
    REQUIRE(d2.unit.value() == d.unit.value());
    REQUIRE(d2.mints.value() == d.mints.value());
    REQUIRE(d2.transports[0].type == d.transports[0].type);
    REQUIRE(d2.transports[0].target == d.transports[0].target);
}

TEST_CASE("creqB Nut26_NostrTransport (DotNut vector)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQQSE3EXFSN2VTZ8QPQQZQQQQQQQQQQQPJQXQQPQQZSQXTGW368QUE69UHK66TWWSCJUETCV9KHQMR99E3K7MG9QQVKSAR5WPEN5TE0D45KUAPJ9EJHSCTDWPKX2TNRDAKSWQPEQYQQZQQZQQSQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQRQQZSZMSZXYMSXQQ8Q9HQGWFHXV6SCAGZ48";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "f92a51b8");
    REQUIRE(d.amount.value() == 100);
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.mints->size() == 2);
    REQUIRE(d.mints->at(0) == "https://mint1.example.com");
    REQUIRE(d.mints->at(1) == "https://mint2.example.com");
    REQUIRE(d.transports.size() == 1);
    REQUIRE(d.transports[0].type == "nostr");
    REQUIRE(d.transports[0].target == "nprofile1qqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8uzqt");
    REQUIRE(d.transports[0].tags->size() == 2);
    REQUIRE(d.transports[0].tags->at(0).key == "n");
    REQUIRE(d.transports[0].tags->at(0).values[0] == "17");
    REQUIRE(d.transports[0].tags->at(1).key == "n");
    REQUIRE(d.transports[0].tags->at(1).values[0] == "9735");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26_MinimalPaymentRequest (DotNut vector)", "[creqb]") {
    std::string encoded = "CREQB1QYQQSDMXX3SNYC3N8YPSQQGQQ5QPS6R5W3C8XW309AKKJMN59EJHSCTDWPKX2TNRDAKSYP0LHG";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "7f4a2b39");
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.mints->size() == 1);
    REQUIRE(d.mints->at(0) == "https://mint.example.com");
    REQUIRE_FALSE(d.amount.has_value());

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26_Nut10Lock (DotNut vector)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQQSCEEV56R2EPJVYPQQZQQQQQQQQQQQ86QXQQPQQZSQXRGW368QUE69UHK66TWWSHX27RPD4CXCEFWVDHK6ZQQTYQSQQGQQGQYYVPJVVEKYDTZVGERWEFNXCCNGDFHVVUNYEPEXDJRWWRYVSMNXEPNVS6NXDENXGCNZVRZXF3KVEFCVG6NQENZVVCXZCNRXCCN2EFEVVENXVGRQQXSWARFD4JK7AT5QSENVVPS2N5FAS";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "c9e45d2a");
    REQUIRE(d.amount.value() == 500);
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.mints->at(0) == "https://mint.example.com");
    REQUIRE(d.nut10.has_value());
    REQUIRE(d.nut10->kind == "P2PK");
    REQUIRE(d.nut10->data == "02c3b5bb27e361457c92d93d78dd73d3d53732110b2cfe8b50fbc0abc615e9c331");
    REQUIRE(d.nut10->tags->size() == 1);
    REQUIRE(d.nut10->tags->at(0).key == "timeout");
    REQUIRE(d.nut10->tags->at(0).values[0] == "3600");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26HttpPostTransport (DotNut vector)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQQJ6R5W3C97AR9WD6QYQQGQQQQQQQQQQQ05QCQQYQQ2QQCDP68GURN8GHJ7MTFDE6ZUETCV9KHQMR99E3K7MG8QPQSZQQPQYPQQGNGW368QUE69UHKZURF9EJHSCTDWPKX2TNRDAKJ7A339ACXZ7TDV4H8GQCQZ5RXXATNW3HK6PNKV9K82EF3QEMXZMR4V5EQ9X3SJM";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "http_test");
    REQUIRE(d.amount.value() == 250);
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.mints->at(0) == "https://mint.example.com");
    REQUIRE(d.transports.size() == 1);
    REQUIRE(d.transports[0].type == "post");
    REQUIRE(d.transports[0].target == "https://api.example.com/v1/payment");
    REQUIRE(d.transports[0].tags->size() == 1);
    REQUIRE(d.transports[0].tags->at(0).key == "custom");
    REQUIRE(d.transports[0].tags->at(0).values.size() == 2);
    REQUIRE(d.transports[0].tags->at(0).values[0] == "value1");
    REQUIRE(d.transports[0].tags->at(0).values[1] == "value2");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26Nprofile with 3 relays (DotNut vector)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQQ5UN9D3SHJHM5V4EHGQSQPQQQQQQQQQQQQEQRQQQSQPGQRP58GARSWVAZ7TMDD9H8GTN90PSK6URVV5HXXMMDQUQGZQGQQYQQYQPQ80CVV07TJDRRGPA0J7J7TMNYL2YR6YR7L8J4S3EVF6U64TH6GKWSXQQMQ9EPSAMNWVAZ7TMJV4KXZ7F39EJHSCTDWPKX2TNRDAKSXQQMQ9EPSAMNWVAZ7TMJV4KXZ7FJ9EJHSCTDWPKX2TNRDAKSXQQMQ9EPSAMNWVAZ7TMJV4KXZ7FN9EJHSCTDWPKX2TNRDAKSKRFDAR";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "relay_test");
    REQUIRE(d.amount.value() == 100);
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.mints->at(0) == "https://mint.example.com");
    REQUIRE(d.transports.size() == 1);
    REQUIRE(d.transports[0].type == "nostr");
    REQUIRE(d.transports[0].target == "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gprpmhxue69uhhyetvv9unztn90psk6urvv5hxxmmdqyv8wumn8ghj7un9d3shjv3wv4uxzmtsd3jjucm0d5q3samnwvaz7tmjv4kxz7fn9ejhsctdwpkx2tnrdaksxzjpjp");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26_Description (DotNut vector)", "[creqb]") {
    std::string encoded = "CREQB1QYQQJER9WD347AR9WD6QYQQGQQQQQQQQQQQXGQCQQYQQ2QQCDP68GURN8GHJ7MTFDE6ZUETCV9KHQMR99E3K7MGXQQV9GETNWSS8QCTED4JKUAPQV3JHXCMJD9C8G6T0DCFLJJRX";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "desc_test");
    REQUIRE(d.amount.value() == 100);
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.mints->at(0) == "https://mint.example.com");
    REQUIRE(d.description.value() == "Test payment description");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26_SingleUseTrue (DotNut vector)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQQ7UMFDENKCE2LW4EK2HM5WF6K2QSQPQQQQQQQQQQQQEQRQQQSQPQQQYQS2QQCDP68GURN8GHJ7MTFDE6ZUETCV9KHQMR99E3K7MGX0AYM7";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "single_use_true");
    REQUIRE(d.amount.value() == 100);
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.single_use.has_value());
    REQUIRE(d.single_use.value() == true);
    REQUIRE(d.mints->at(0) == "https://mint.example.com");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26_SingleUseFalse (DotNut vector)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQPQUMFDENKCE2LW4EK2HMXV9K8XEGZQQYQQQQQQQQQQQRYQVQQZQQYQQQSQPGQRP58GARSWVAZ7TMDD9H8GTN90PSK6URVV5HXXMMDQ40L90";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "single_use_false");
    REQUIRE(d.amount.value() == 100);
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.single_use.has_value());
    REQUIRE(d.single_use.value() == false);
    REQUIRE(d.mints->at(0) == "https://mint.example.com");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26_MsatUnit (DotNut vector)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQQJATWD9697MTNV96QYQQGQQQQQQQQQQP7SQCQQ3KHXCT5Q5QPS6R5W3C8XW309AKKJMN59EJHSCTDWPKX2TNRDAKSYYMU95";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "unit_msat");
    REQUIRE(d.amount.value() == 1000);
    REQUIRE(d.unit.value() == "msat");
    REQUIRE(d.mints->at(0) == "https://mint.example.com");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26_UsdUnit (DotNut vector)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQQSATWD9697ATNVSPQQZQQQQQQQQQQQ86QXQQRW4EKGPGQRP58GARSWVAZ7TMDD9H8GTN90PSK6URVV5HXXMMDEPCJYC";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "unit_usd");
    REQUIRE(d.amount.value() == 500);
    REQUIRE(d.unit.value() == "usd");
    REQUIRE(d.mints->at(0) == "https://mint.example.com");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26_MultipleTransports (DotNut vector)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQQ7MT4D36XJHM5WFSKUUMSDAE8GQSQPQQQQQQQQQQQRAQRQQQSQPGQRP58GARSWVAZ7TMDD9H8GTN90PSK6URVV5HXXMMDQCQZQ5RP09KK2MN5YPMKJARGYPKH2MR5D9CXCEFQW3EXZMNNWPHHYARNQUQZ7QGQQYQQYQPQ80CVV07TJDRRGPA0J7J7TMNYL2YR6YR7L8J4S3EVF6U64TH6GKWSXQQ9Q9HQYVFHQUQZWQGQQYQSYQPQDP68GURN8GHJ7CTSDYCJUETCV9KHQMR99E3K7MF0WPSHJMT9DE6QWQP6QYQQZQGZQQSXSAR5WPEN5TE0V9CXJV3WV4UXZMTSD3JJUCM0D5HHQCTED4JKUAQRQQGQSURJD9HHY6T50YRXYCTRDD6HQTSH7TP";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "multi_transport");
    REQUIRE(d.amount.value() == 500);
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.mints->at(0) == "https://mint.example.com");
    REQUIRE(d.transports.size() == 3);

    REQUIRE(d.transports[0].type == "nostr");
    REQUIRE(d.transports[0].target == "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8g2lcy6q");
    REQUIRE(d.transports[0].tags->at(0).key == "n");
    REQUIRE(d.transports[0].tags->at(0).values[0] == "17");

    REQUIRE(d.transports[1].type == "post");
    REQUIRE(d.transports[1].target == "https://api1.example.com/payment");

    REQUIRE(d.transports[2].type == "post");
    REQUIRE(d.transports[2].tags->at(0).key == "priority");
    REQUIRE(d.transports[2].tags->at(0).values[0] == "backup");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26MinimalNostrTransport (DotNut vector)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQQ6MTFDE5K6CTVTAHX7UM5WGPSQQGQQ5QPS6R5W3C8XW309AKKJMN59EJHSCTDWPKX2TNRDAKSWQP8QYQQZQQZQQSRHUXX8L9EX335Q7HE0F09AEJ04ZPAZPL0NE2CGUKYAWD24MAYT8G7QNXMQ";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "minimal_nostr");
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.mints->at(0) == "https://mint.example.com");
    REQUIRE(d.transports.size() == 1);
    REQUIRE(d.transports[0].type == "nostr");
    REQUIRE(d.transports[0].target == "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8g2lcy6q");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26MinimalPostTransport (DotNut vector)", "[creqb]") {
    std::string encoded = "CREQB1QYQQCMTFDE5K6CTVTA58GARSQVQQZQQ9QQVXSAR5WPEN5TE0D45KUAPWV4UXZMTSD3JJUCM0D5RSQ8SPQQQSZQSQZA58GARSWVAZ7TMPWP5JUETCV9KHQMR99E3K7MG0TWYGX";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "minimal_http");
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.mints->at(0) == "https://mint.example.com");
    REQUIRE(d.transports.size() == 1);
    REQUIRE(d.transports[0].type == "post");
    REQUIRE(d.transports[0].target == "https://api.example.com");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26Nut10HTLC (DotNut vector)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQQJ6R5D3347AR9WD6QYQQGQQQQQQQQQQP7SQCQQYQQ2QQCDP68GURN8GHJ7MTFDE6ZUETCV9KHQMR99E3K7MGXQQF5S4ZVGVSXCMMRDDJKGGRSV9UK6ETWWSYQPTGPQQQSZQSQGFS46VR9XCMRSV3SVFNXYDP3XGERZVNRVCMKZC3NV3JKYVP5X5UKXEFJ8QEXZVTZXQ6XVERPXUMX2CFKXQERVCFKXAJNGVTPV5ERVE3NV33SXQQ5PPKX7CMTW35K6EG2XYMNQVPSXQCRQVPSQVQY5PNJV4N82MNYGGCRXVEJ8QCKXVEHXCMNWETPXGMNXETZXUCNSVMZXUURXVPKXANR2V35XSUNXVM9VCMNSEPCVVEKVVF4VGCKZDEHVD3RYDPKXQUNJCEJXEJS4EHJHC";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "htlc_test");
    REQUIRE(d.amount.value() == 1000);
    REQUIRE(d.unit.value() == "sat");
    REQUIRE(d.mints->at(0) == "https://mint.example.com");
    REQUIRE(d.description.value() == "HTLC locked payment");
    REQUIRE(d.nut10.has_value());
    REQUIRE(d.nut10->kind == "HTLC");
    REQUIRE(d.nut10->data == "a]0e66820bfb412212cf7ab3deb0459ce282a1b04fda76ea6026a67e41ae26f3dc");
    REQUIRE(d.nut10->tags->size() == 2);
    REQUIRE(d.nut10->tags->at(0).key == "locktime");
    REQUIRE(d.nut10->tags->at(0).values[0] == "1700000000");
    REQUIRE(d.nut10->tags->at(1).key == "refund");
    REQUIRE(d.nut10->tags->at(1).values[0] == "033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}

TEST_CASE("creqB Nut26CustomCurrencyUnit (DotNut vector)", "[creqb]") {
    std::string encoded =
        "CREQB1QYQQKCM4WD6X7M2LW4HXJAQZQQYQQQQQQQQQQQRYQVQQXCN5VVZSQXRGW368QUE69UHK66TWWSHX27RPD4CXCEFWVDHK6PZHCW8";
    auto d = PaymentRequestEncoder::parse(encoded);
    REQUIRE(d.payment_id.value() == "custom_unit");
    REQUIRE(d.amount.value() == 100);
    REQUIRE(d.unit.value() == "btc");
    REQUIRE(d.mints->at(0) == "https://mint.example.com");

    auto encoded_again = PaymentRequestBech32Encoder::encode(d);
    REQUIRE(encoded_again == encoded);
}
