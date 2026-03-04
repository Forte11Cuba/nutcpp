#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include "nutcpp/nuts/nut10_secret.h"
#include "nutcpp/types/secret.h"

using namespace nutcpp;
using json = nlohmann::json;

// ============================================================
// NUT-10: Nut10ProofSecret
// ============================================================

TEST_CASE("nut10: Nut10ProofSecret JSON roundtrip", "[nut10]") {
    Nut10ProofSecret ps;
    ps.nonce = "da62796403af76c80cd6ce9153ed3746";
    ps.data = "023192200a0cfd3867e48eb63b03ff599c7e46c8f4e41146b2d281173ca6c50c";
    ps.tags = std::vector<std::vector<std::string>>{
        {"pubkeys", "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904"},
        {"locktime", "1689418329"},
        {"refund", "033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e"}
    };

    json j;
    to_json(j, ps);
    REQUIRE(j["nonce"] == "da62796403af76c80cd6ce9153ed3746");
    REQUIRE(j["data"] == "023192200a0cfd3867e48eb63b03ff599c7e46c8f4e41146b2d281173ca6c50c");
    REQUIRE(j["tags"].size() == 3);
    REQUIRE(j["tags"][0][0] == "pubkeys");
    REQUIRE(j["tags"][1][0] == "locktime");
    REQUIRE(j["tags"][2][0] == "refund");

    Nut10ProofSecret ps2;
    from_json(j, ps2);
    REQUIRE(ps == ps2);
}

TEST_CASE("nut10: Nut10ProofSecret without tags", "[nut10]") {
    Nut10ProofSecret ps;
    ps.nonce = "abc123";
    ps.data = "deadbeef";

    json j;
    to_json(j, ps);
    REQUIRE_FALSE(j.contains("tags"));

    Nut10ProofSecret ps2;
    from_json(j, ps2);
    REQUIRE(ps == ps2);
}

TEST_CASE("nut10: Nut10ProofSecret equality", "[nut10]") {
    Nut10ProofSecret a;
    a.nonce = "abc";
    a.data = "def";
    a.tags = std::vector<std::vector<std::string>>{{"key", "val"}};

    Nut10ProofSecret b = a;
    REQUIRE(a == b);

    b.nonce = "xyz";
    REQUIRE(a != b);

    b = a;
    b.tags = std::vector<std::vector<std::string>>{{"key", "val2"}};
    REQUIRE(a != b);

    Nut10ProofSecret c;
    c.nonce = "abc";
    c.data = "def";
    // c has no tags, a has tags
    REQUIRE(a != c);
}

TEST_CASE("nut10: Nut10ProofSecret find_tag", "[nut10]") {
    Nut10ProofSecret ps;
    ps.nonce = "test";
    ps.data = "test";
    ps.tags = std::vector<std::vector<std::string>>{
        {"sigflag", "SIG_ALL"},
        {"locktime", "12345"},
        {"pubkeys", "02aaa", "02bbb"}
    };

    auto* sigflag = ps.find_tag("sigflag");
    REQUIRE(sigflag != nullptr);
    REQUIRE(sigflag->size() == 2);
    REQUIRE((*sigflag)[1] == "SIG_ALL");

    auto* locktime = ps.find_tag("locktime");
    REQUIRE(locktime != nullptr);
    REQUIRE((*locktime)[1] == "12345");

    auto* pubkeys = ps.find_tag("pubkeys");
    REQUIRE(pubkeys != nullptr);
    REQUIRE(pubkeys->size() == 3); // "pubkeys", "02aaa", "02bbb"

    REQUIRE(ps.find_tag("nonexistent") == nullptr);
}

// ============================================================
// NUT-10: Nut10Secret
// ============================================================

TEST_CASE("nut10: Nut10Secret serialize as JSON array", "[nut10]") {
    auto ps = std::make_shared<Nut10ProofSecret>();
    ps->nonce = "c7f280eb55c1e8564e03db06973e94bc9b666d9e1ca42ad278408fe625950303";
    ps->data = "030d8acedfe072c9fa449a1efe0817157403fbec460d8e79f957966056e5dd76c1";
    ps->tags = std::vector<std::vector<std::string>>{{"sigflag", "SIG_ALL"}};

    Nut10Secret secret("P2PK", ps);
    auto s = secret.to_json_string();
    auto j = json::parse(s);

    REQUIRE(j.is_array());
    REQUIRE(j.size() == 2);
    REQUIRE(j[0] == "P2PK");
    REQUIRE(j[1]["nonce"] == ps->nonce);
    REQUIRE(j[1]["data"] == ps->data);
    REQUIRE(j[1]["tags"][0][0] == "sigflag");
    REQUIRE(j[1]["tags"][0][1] == "SIG_ALL");
}

TEST_CASE("nut10: Nut10Secret get_bytes produces JSON UTF-8", "[nut10]") {
    auto ps = std::make_shared<Nut10ProofSecret>();
    ps->nonce = "test_nonce";
    ps->data = "test_data";

    Nut10Secret secret("P2PK", ps);
    auto bytes = secret.get_bytes();
    std::string s(bytes.begin(), bytes.end());
    auto j = json::parse(s);
    REQUIRE(j[0] == "P2PK");
    REQUIRE(j[1]["nonce"] == "test_nonce");
}

TEST_CASE("nut10: Nut10Secret get_bytes preserves original string", "[nut10]") {
    std::string original = "[\"P2PK\",{\"nonce\":\"abc\",\"data\":\"def\"}]";
    auto ps = std::make_shared<Nut10ProofSecret>();
    ps->nonce = "abc";
    ps->data = "def";

    Nut10Secret secret("P2PK", ps, original);
    auto bytes = secret.get_bytes();
    std::string result(bytes.begin(), bytes.end());
    REQUIRE(result == original);
}

TEST_CASE("nut10: Nut10Secret to_curve hashes correctly", "[nut10]") {
    auto ps = std::make_shared<Nut10ProofSecret>();
    ps->nonce = "test_nonce";
    ps->data = "test_data";

    Nut10Secret secret("P2PK", ps);
    // Should not throw — produces a valid point on secp256k1
    auto point = secret.to_curve();
    REQUIRE(point.to_hex().size() == 66);
}

// ============================================================
// parse_secret dispatch
// ============================================================

TEST_CASE("nut10: parse_secret with plain string", "[nut10]") {
    auto secret = parse_secret("daf4dd00a2b68a0858a80450f52c8a7d2ccf87d375e43e216e0c571f089f63e9");
    auto* ss = dynamic_cast<StringSecret*>(secret.get());
    REQUIRE(ss != nullptr);
    REQUIRE(ss->value() == "daf4dd00a2b68a0858a80450f52c8a7d2ccf87d375e43e216e0c571f089f63e9");
}

TEST_CASE("nut10: parse_secret with P2PK structured secret", "[nut10]") {
    std::string secret_str = "[\"P2PK\",{\"nonce\":\"859d4935c4907062a6297cf4e663e2835d90d97ecdd510745d32f6816323a41f\",\"data\":\"0249098aa8b9d2fbec49ff8598feb17b592b986e62319a4fa488a3dc36387157a7\",\"tags\":[[\"sigflag\",\"SIG_INPUTS\"]]}]";
    auto secret = parse_secret(secret_str);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    REQUIRE(nut10 != nullptr);
    REQUIRE(nut10->key() == "P2PK");
    REQUIRE(nut10->proof_secret()->nonce == "859d4935c4907062a6297cf4e663e2835d90d97ecdd510745d32f6816323a41f");
    REQUIRE(nut10->proof_secret()->data == "0249098aa8b9d2fbec49ff8598feb17b592b986e62319a4fa488a3dc36387157a7");
    auto* sigflag = nut10->proof_secret()->find_tag("sigflag");
    REQUIRE(sigflag != nullptr);
    REQUIRE((*sigflag)[1] == "SIG_INPUTS");
}

TEST_CASE("nut10: parse_secret with HTLC structured secret", "[nut10]") {
    std::string secret_str = "[\"HTLC\",{\"nonce\":\"da62796403af76c80cd6ce9153ed3746\",\"data\":\"023192200a0cfd3867e48eb63b03ff599c7e46c8f4e41146b2d281173ca6c50c\",\"tags\":[[\"pubkeys\",\"02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904\"],[\"locktime\",\"1689418329\"],[\"refund\",\"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e\"]]}]";
    auto secret = parse_secret(secret_str);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    REQUIRE(nut10 != nullptr);
    REQUIRE(nut10->key() == "HTLC");
    REQUIRE(nut10->proof_secret()->data == "023192200a0cfd3867e48eb63b03ff599c7e46c8f4e41146b2d281173ca6c50c");
    REQUIRE(nut10->proof_secret()->tags->size() == 3);
}

TEST_CASE("nut10: parse_secret with NUT-11 spec multisig secret", "[nut10]") {
    // NUT-11 spec example: multisig P2PK with locktime, refund, n_sigs, pubkeys
    std::string secret_str = "[\"P2PK\",{\"nonce\":\"da62796403af76c80cd6ce9153ed3746\",\"data\":\"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e\",\"tags\":[[\"sigflag\",\"SIG_ALL\"],[\"n_sigs\",\"2\"],[\"locktime\",\"1689418329\"],[\"refund\",\"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e\",\"02e2aeb97f47690e3c418592a5bcda77282d1339a3017f5558928c2441b7731d50\"],[\"pubkeys\",\"02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904\",\"023192200a0cfd3867e48eb63b03ff599c7e46c8f4e41146b2d281173ca6c50c54\"]]}]";
    auto secret = parse_secret(secret_str);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    REQUIRE(nut10 != nullptr);
    REQUIRE(nut10->key() == "P2PK");
    REQUIRE(nut10->proof_secret()->data == "033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e");
    REQUIRE(nut10->proof_secret()->tags->size() == 5);
    // Verify all tags parsed correctly
    auto* sigflag = nut10->proof_secret()->find_tag("sigflag");
    REQUIRE(sigflag != nullptr);
    REQUIRE((*sigflag)[1] == "SIG_ALL");
    auto* n_sigs = nut10->proof_secret()->find_tag("n_sigs");
    REQUIRE(n_sigs != nullptr);
    REQUIRE((*n_sigs)[1] == "2");
    auto* locktime = nut10->proof_secret()->find_tag("locktime");
    REQUIRE(locktime != nullptr);
    REQUIRE((*locktime)[1] == "1689418329");
    auto* refund = nut10->proof_secret()->find_tag("refund");
    REQUIRE(refund != nullptr);
    REQUIRE(refund->size() == 3); // "refund" + 2 pubkeys
    auto* pubkeys = nut10->proof_secret()->find_tag("pubkeys");
    REQUIRE(pubkeys != nullptr);
    REQUIRE(pubkeys->size() == 3); // "pubkeys" + 2 pubkeys
}

TEST_CASE("nut10: parse_secret from DotNut Nut11 valid proof secret field", "[nut10]") {
    // From DotNut UnitTest1.cs Nut11_Signatures — this is how secrets appear inside Proof JSON:
    // the secret is a JSON string containing the escaped array
    std::string proof_json = "{\"amount\":1,\"secret\":\"[\\\"P2PK\\\",{\\\"nonce\\\":\\\"859d4935c4907062a6297cf4e663e2835d90d97ecdd510745d32f6816323a41f\\\",\\\"data\\\":\\\"0249098aa8b9d2fbec49ff8598feb17b592b986e62319a4fa488a3dc36387157a7\\\",\\\"tags\\\":[[\\\"sigflag\\\",\\\"SIG_INPUTS\\\"]]}]\",\"C\":\"02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904\",\"id\":\"009a1f293253e41e\",\"witness\":\"{\\\"signatures\\\":[\\\"60f3c9b766770b46caac1d27e1ae6b77c8866ebaeba0b9489fe6a15a837eaa6fcd6eaa825499c72ac342983983fd3ba3a8a41f56677cc99ffd73da68b59e1383\\\"]}\"}";
    auto j = json::parse(proof_json);
    // Extract the secret string as Proof would store it
    std::string secret_str = j["secret"].get<std::string>();
    auto secret = parse_secret(secret_str);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    REQUIRE(nut10 != nullptr);
    REQUIRE(nut10->key() == "P2PK");
    REQUIRE(nut10->proof_secret()->nonce == "859d4935c4907062a6297cf4e663e2835d90d97ecdd510745d32f6816323a41f");
    REQUIRE(nut10->proof_secret()->data == "0249098aa8b9d2fbec49ff8598feb17b592b986e62319a4fa488a3dc36387157a7");
    // Verify get_bytes preserves exact original for signature verification
    auto bytes = secret->get_bytes();
    std::string bytes_str(bytes.begin(), bytes.end());
    REQUIRE(bytes_str == secret_str);
}

TEST_CASE("nut10: parse_secret from DotNut HTLC test vector", "[nut10]") {
    // From DotNut UnitTest1.cs Nut14Tests_HTLCSecret (line 524-525)
    std::string htlc_str = "[\"HTLC\",{\"nonce\":\"da62796403af76c80cd6ce9153ed3746\",\"data\":\"023192200a0cfd3867e48eb63b03ff599c7e46c8f4e41146b2d281173ca6c50c\",\"tags\":[[\"pubkeys\",\"02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904\"],[\"locktime\",\"1689418329\"],[\"refund\",\"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e\"]]}]";
    auto secret = parse_secret(htlc_str);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    REQUIRE(nut10 != nullptr);
    REQUIRE(nut10->key() == "HTLC");
    // Data is the hashlock (SHA256 hash, 64 hex chars)
    REQUIRE(nut10->proof_secret()->data == "023192200a0cfd3867e48eb63b03ff599c7e46c8f4e41146b2d281173ca6c50c");
    // Verify tags
    auto* pubkeys_tag = nut10->proof_secret()->find_tag("pubkeys");
    REQUIRE(pubkeys_tag != nullptr);
    REQUIRE((*pubkeys_tag)[1] == "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904");
    auto* locktime_tag = nut10->proof_secret()->find_tag("locktime");
    REQUIRE(locktime_tag != nullptr);
    REQUIRE((*locktime_tag)[1] == "1689418329");
    auto* refund_tag = nut10->proof_secret()->find_tag("refund");
    REQUIRE(refund_tag != nullptr);
    REQUIRE((*refund_tag)[1] == "033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e");
}

TEST_CASE("nut10: Nut10ProofSecret empty tags roundtrip preserves empty array", "[nut10]") {
    Nut10ProofSecret ps;
    ps.nonce = "abc";
    ps.data = "def";
    ps.tags = std::vector<std::vector<std::string>>{}; // explicit empty

    json j;
    to_json(j, ps);
    REQUIRE(j.contains("tags"));
    REQUIRE(j["tags"].is_array());
    REQUIRE(j["tags"].empty());

    Nut10ProofSecret ps2;
    from_json(j, ps2);
    REQUIRE(ps2.tags.has_value());
    REQUIRE(ps2.tags->empty());
    REQUIRE(ps == ps2);
}

TEST_CASE("nut10: Nut10Secret rejects null proof_secret", "[nut10]") {
    REQUIRE_THROWS_AS(
        Nut10Secret("P2PK", nullptr),
        std::invalid_argument
    );
    REQUIRE_THROWS_AS(
        Nut10Secret("P2PK", nullptr, "original"),
        std::invalid_argument
    );
}

TEST_CASE("nut10: parse_secret with invalid JSON falls back to StringSecret", "[nut10]") {
    auto secret = parse_secret("[not valid json");
    auto* ss = dynamic_cast<StringSecret*>(secret.get());
    REQUIRE(ss != nullptr);
    REQUIRE(ss->value() == "[not valid json");
}

TEST_CASE("nut10: parse_secret with malformed P2PK payload throws", "[nut10]") {
    // Recognized key "P2PK" but nonce is int instead of string — schema error should propagate
    REQUIRE_THROWS(parse_secret("[\"P2PK\",{\"nonce\":1}]"));
    // Recognized key "HTLC" but missing required "nonce" field
    REQUIRE_THROWS(parse_secret("[\"HTLC\",{\"data\":\"abc\"}]"));
}

TEST_CASE("nut10: parse_secret with unknown key falls back to StringSecret", "[nut10]") {
    auto secret = parse_secret("[\"UNKNOWN\",{\"nonce\":\"abc\",\"data\":\"def\"}]");
    auto* ss = dynamic_cast<StringSecret*>(secret.get());
    REQUIRE(ss != nullptr);
}

TEST_CASE("nut10: parse_secret preserves original bytes for get_bytes", "[nut10]") {
    std::string secret_str = "[\"P2PK\",{\"nonce\":\"abc\",\"data\":\"def\",\"tags\":[[\"sigflag\",\"SIG_INPUTS\"]]}]";
    auto secret = parse_secret(secret_str);
    auto bytes = secret->get_bytes();
    std::string result(bytes.begin(), bytes.end());
    REQUIRE(result == secret_str);
}
