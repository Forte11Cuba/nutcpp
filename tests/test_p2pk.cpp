#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include "nutcpp/nuts/nut10_secret.h"
#include "nutcpp/nuts/p2pk.h"
#include "nutcpp/nuts/htlc.h"
#include "nutcpp/types/secret.h"
#include "nutcpp/encoding/convert_utils.h"

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

// ============================================================
// NUT-11: P2PK — parse_secret dispatches to P2PKProofSecret
// ============================================================

TEST_CASE("p2pk: parse_secret creates P2PKProofSecret for P2PK key", "[p2pk]") {
    std::string s = "[\"P2PK\",{\"nonce\":\"abc\",\"data\":\"0249098aa8b9d2fbec49ff8598feb17b592b986e62319a4fa488a3dc36387157a7\",\"tags\":[[\"sigflag\",\"SIG_INPUTS\"]]}]";
    auto secret = parse_secret(s);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    REQUIRE(nut10 != nullptr);
    auto* p2pk_ps = dynamic_cast<P2PKProofSecret*>(nut10->proof_secret().get());
    REQUIRE(p2pk_ps != nullptr);
}

// ============================================================
// NUT-11: P2PKBuilder
// ============================================================

TEST_CASE("p2pk: P2PKBuilder build and load roundtrip", "[p2pk]") {
    PubKey pk1("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    PubKey pk2("02142715675faf8da1ecc4d51e0b9e539fa0d52fdd96ed60dbe99adb15d6b05ad9");
    PubKey refund_pk("033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e");

    P2PKBuilder builder;
    builder.pubkeys = {pk1, pk2};
    builder.signature_threshold = 2;
    builder.lock = 21000000000;
    builder.refund_pubkeys = {refund_pk};
    builder.sig_flag = "SIG_INPUTS";
    builder.nonce = "test_nonce";

    auto ps = builder.build();
    REQUIRE(ps.data == pk1.to_hex());
    REQUIRE(ps.nonce == "test_nonce");
    REQUIRE(ps.tags.has_value());

    // Roundtrip via load
    auto loaded = P2PKBuilder::load(ps);
    REQUIRE(loaded.pubkeys.size() == 2);
    REQUIRE(loaded.pubkeys[0] == pk1);
    REQUIRE(loaded.pubkeys[1] == pk2);
    REQUIRE(loaded.signature_threshold == 2);
    REQUIRE(loaded.lock.value() == 21000000000);
    REQUIRE(loaded.refund_pubkeys.size() == 1);
    REQUIRE(loaded.refund_pubkeys[0] == refund_pk);
    REQUIRE(loaded.sig_flag == "SIG_INPUTS");
}

TEST_CASE("p2pk: P2PKBuilder validate rejects bad threshold", "[p2pk]") {
    P2PKBuilder builder;
    builder.pubkeys = {PubKey("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")};
    builder.signature_threshold = 2; // only 1 pubkey
    REQUIRE_THROWS_AS(builder.build(), std::invalid_argument);
}

// ============================================================
// NUT-11: P2PK Sign + Verify with DotNut test vectors
// ============================================================

// Helper: extract P2PKProofSecret from a proof JSON string
static P2PKProofSecret* extract_p2pk(const std::string& proof_json,
                                      std::unique_ptr<ISecret>& secret_out) {
    auto j = json::parse(proof_json);
    std::string secret_str = j["secret"].get<std::string>();
    secret_out = parse_secret(secret_str);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret_out.get());
    if (!nut10) return nullptr;
    return dynamic_cast<P2PKProofSecret*>(nut10->proof_secret().get());
}

static P2PKWitness parse_witness(const std::string& proof_json) {
    auto j = json::parse(proof_json);
    std::string witness_str = j["witness"].get<std::string>();
    auto wj = json::parse(witness_str);
    P2PKWitness w;
    from_json(wj, w);
    return w;
}

TEST_CASE("p2pk: valid SIG_INPUTS signature (DotNut vector)", "[p2pk]") {
    std::string proof_json = "{\"amount\":1,\"secret\":\"[\\\"P2PK\\\",{\\\"nonce\\\":\\\"859d4935c4907062a6297cf4e663e2835d90d97ecdd510745d32f6816323a41f\\\",\\\"data\\\":\\\"0249098aa8b9d2fbec49ff8598feb17b592b986e62319a4fa488a3dc36387157a7\\\",\\\"tags\\\":[[\\\"sigflag\\\",\\\"SIG_INPUTS\\\"]]}]\",\"C\":\"02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904\",\"id\":\"009a1f293253e41e\",\"witness\":\"{\\\"signatures\\\":[\\\"60f3c9b766770b46caac1d27e1ae6b77c8866ebaeba0b9489fe6a15a837eaa6fcd6eaa825499c72ac342983983fd3ba3a8a41f56677cc99ffd73da68b59e1383\\\"]}\"}";
    std::unique_ptr<ISecret> secret;
    auto* p2pk_ps = extract_p2pk(proof_json, secret);
    REQUIRE(p2pk_ps != nullptr);
    auto witness = parse_witness(proof_json);
    REQUIRE(p2pk_ps->verify_witness(*secret, witness));
}

TEST_CASE("p2pk: invalid SIG_INPUTS signature (DotNut vector)", "[p2pk]") {
    std::string proof_json = "{\n  \"amount\": 1,\n  \"secret\": \"[\\\"P2PK\\\",{\\\"nonce\\\":\\\"859d4935c4907062a6297cf4e663e2835d90d97ecdd510745d32f6816323a41f\\\",\\\"data\\\":\\\"0249098aa8b9d2fbec49ff8598feb17b592b986e62319a4fa488a3dc36387157a7\\\",\\\"tags\\\":[[\\\"sigflag\\\",\\\"SIG_INPUTS\\\"]]}]\",\n  \"C\": \"02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904\",\n  \"id\": \"009a1f293253e41e\",\n  \"witness\": \"{\\\"signatures\\\":[\\\"83564aca48c668f50d022a426ce0ed19d3a9bdcffeeaee0dc1e7ea7e98e9eff1840fcc821724f623468c94f72a8b0a7280fa9ef5a54a1b130ef3055217f467b3\\\"]}\"\n}";
    std::unique_ptr<ISecret> secret;
    auto* p2pk_ps = extract_p2pk(proof_json, secret);
    REQUIRE(p2pk_ps != nullptr);
    auto witness = parse_witness(proof_json);
    REQUIRE_FALSE(p2pk_ps->verify_witness(*secret, witness));
}

TEST_CASE("p2pk: valid multisig 2-of-3 (DotNut vector)", "[p2pk]") {
    std::string proof_json = "{\"amount\":1,\"secret\":\"[\\\"P2PK\\\",{\\\"nonce\\\":\\\"0ed3fcb22c649dd7bbbdcca36e0c52d4f0187dd3b6a19efcc2bfbebb5f85b2a1\\\",\\\"data\\\":\\\"0249098aa8b9d2fbec49ff8598feb17b592b986e62319a4fa488a3dc36387157a7\\\",\\\"tags\\\":[[\\\"pubkeys\\\",\\\"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\\\",\\\"02142715675faf8da1ecc4d51e0b9e539fa0d52fdd96ed60dbe99adb15d6b05ad9\\\"],[\\\"n_sigs\\\",\\\"2\\\"],[\\\"sigflag\\\",\\\"SIG_INPUTS\\\"]]}]\",\"C\":\"02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904\",\"id\":\"009a1f293253e41e\",\"witness\":\"{\\\"signatures\\\":[\\\"83564aca48c668f50d022a426ce0ed19d3a9bdcffeeaee0dc1e7ea7e98e9eff1840fcc821724f623468c94f72a8b0a7280fa9ef5a54a1b130ef3055217f467b3\\\",\\\"9a72ca2d4d5075be5b511ee48dbc5e45f259bcf4a4e8bf18587f433098a9cd61ff9737dc6e8022de57c76560214c4568377792d4c2c6432886cc7050487a1f22\\\"]}\"}";
    std::unique_ptr<ISecret> secret;
    auto* p2pk_ps = extract_p2pk(proof_json, secret);
    REQUIRE(p2pk_ps != nullptr);
    auto witness = parse_witness(proof_json);
    REQUIRE(p2pk_ps->verify_witness(*secret, witness));
}

TEST_CASE("p2pk: invalid multisig — only 1 of 2 required (DotNut vector)", "[p2pk]") {
    std::string proof_json = "{\"amount\":1,\"secret\":\"[\\\"P2PK\\\",{\\\"nonce\\\":\\\"0ed3fcb22c649dd7bbbdcca36e0c52d4f0187dd3b6a19efcc2bfbebb5f85b2a1\\\",\\\"data\\\":\\\"0249098aa8b9d2fbec49ff8598feb17b592b986e62319a4fa488a3dc36387157a7\\\",\\\"tags\\\":[[\\\"pubkeys\\\",\\\"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\\\",\\\"02142715675faf8da1ecc4d51e0b9e539fa0d52fdd96ed60dbe99adb15d6b05ad9\\\"],[\\\"n_sigs\\\",\\\"2\\\"],[\\\"sigflag\\\",\\\"SIG_INPUTS\\\"]]}]\",\"C\":\"02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904\",\"id\":\"009a1f293253e41e\",\"witness\":\"{\\\"signatures\\\":[\\\"83564aca48c668f50d022a426ce0ed19d3a9bdcffeeaee0dc1e7ea7e98e9eff1840fcc821724f623468c94f72a8b0a7280fa9ef5a54a1b130ef3055217f467b3\\\"]}\"}";
    std::unique_ptr<ISecret> secret;
    auto* p2pk_ps = extract_p2pk(proof_json, secret);
    REQUIRE(p2pk_ps != nullptr);
    auto witness = parse_witness(proof_json);
    REQUIRE_FALSE(p2pk_ps->verify_witness(*secret, witness));
}

TEST_CASE("p2pk: valid refund path — locktime expired (DotNut vector)", "[p2pk]") {
    std::string proof_json = "{\n  \"amount\": 64,\n  \"C\": \"0257353051c02e2d650dede3159915c8be123ba4f47cf33183c7fedd20bd91a79b\",\n  \"id\": \"001b6c716bf42c7e\",\n  \"secret\": \"[\\\"P2PK\\\",{\\\"nonce\\\":\\\"4bc88ee09d1886c7461d45da205ca3274e1e3d9da2667c4865045cb18265a407\\\",\\\"data\\\":\\\"03d5edeb839be873df2348785506d36565f3b8f390fb931709a422b5a247ddefb1\\\",\\\"tags\\\":[[\\\"locktime\\\",\\\"21\\\"],[\\\"refund\\\",\\\"0234ad87e907e117db1590cc20a3942ffdfd5137aa563d36095d5cf5f96bada122\\\"]]}]\",\n  \"witness\": \"{\\\"signatures\\\":[\\\"b316c2ff9c15f0c5c3d230e99ad94bc76a11dfccbdc820366a3db7210288f22ef6cedcded1152904ec31056d1d5176d83a2d96df5cd4ff86afdde1c90c63af5e\\\"]}\"\n}";
    std::unique_ptr<ISecret> secret;
    auto* p2pk_ps = extract_p2pk(proof_json, secret);
    REQUIRE(p2pk_ps != nullptr);
    auto witness = parse_witness(proof_json);
    // locktime=21 (unix epoch 21) is long expired
    REQUIRE(p2pk_ps->verify_witness(*secret, witness));
}

TEST_CASE("p2pk: invalid refund path — locktime not expired (DotNut vector)", "[p2pk]") {
    std::string proof_json = "{\n  \"amount\": 64,\n  \"C\": \"0215865e3b30bdf6f5cdc1ee2c33379d5629bdf2eff2595603d939ff8c65d80586\",\n  \"id\": \"001b6c716bf42c7e\",\n  \"secret\": \"[\\\"P2PK\\\",{\\\"nonce\\\":\\\"0c3d085898f1abf2b5521035f4d0f4ecf68c6a5109f6bc836833a1188f06be65\\\",\\\"data\\\":\\\"03206e0d488387a816bbafd957be51b073432c6c7a403ec4c2a0b27647326c5150\\\",\\\"tags\\\":[[\\\"locktime\\\",\\\"99999999999\\\"],[\\\"refund\\\",\\\"026acbcd0fff3a424499c83ec892d3155c9d1984438659f448d9d0f1af3e92276a\\\"]]}]\",\n  \"witness\": \"{\\\"signatures\\\":[\\\"e5b10d7627ab39bd0cefa219c63752a0026aa5ae754b91a0c7ee2596222f87942c442aca2957166a6b468350c09c9968792784d2ae7c42fc91739b55689f4c7a\\\"]}\"\n}";
    std::unique_ptr<ISecret> secret;
    auto* p2pk_ps = extract_p2pk(proof_json, secret);
    REQUIRE(p2pk_ps != nullptr);
    auto witness = parse_witness(proof_json);
    // locktime=99999999999 is far in the future
    REQUIRE_FALSE(p2pk_ps->verify_witness(*secret, witness));
}

// ============================================================
// NUT-11: New P2PK Rules (post PR #315)
// ============================================================

TEST_CASE("p2pk: post-locktime standard path valid (DotNut New_P2PkRules)", "[p2pk]") {
    // After locktime, proofs remain spendable via normal path
    std::string proof_json = "{\n  \"amount\": 64,\n  \"C\": \"02d7cd858d866fca404b5cb1ffd813946e6d19efa1af00d654080fd20266bdc0b1\",\n  \"id\": \"001b6c716bf42c7e\",\n  \"secret\": \"[\\\"P2PK\\\",{\\\"nonce\\\":\\\"395162bf2d0add3c66aea9f22c45251dbee6e04bd9282addbb366a94cd4fb482\\\",\\\"data\\\":\\\"03ab50a667926fac858bac540766254c14b2b0334d10e8ec766455310224bbecf4\\\",\\\"tags\\\":[[\\\"locktime\\\",\\\"21\\\"],[\\\"pubkeys\\\",\\\"0229a91adec8dd9badb228c628a07fc1bf707a9b7d95dd505c490b1766fa7dc541\\\",\\\"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e\\\"],[\\\"n_sigs\\\",\\\"2\\\"],[\\\"refund\\\",\\\"03ab50a667926fac858bac540766254c14b2b0334d10e8ec766455310224bbecf4\\\",\\\"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e\\\"]]}]\"\n}";
    auto j = json::parse(proof_json);
    std::string secret_str = j["secret"].get<std::string>();
    auto secret = parse_secret(secret_str);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    REQUIRE(nut10 != nullptr);
    auto* p2pk_ps = dynamic_cast<P2PKProofSecret*>(nut10->proof_secret().get());
    REQUIRE(p2pk_ps != nullptr);

    // Standard path witness with n_sigs=2
    std::string witness_json = "{\"signatures\":[\"6a4dd46f929b4747efe7380d655be5cfc0ea943c679a409ea16d4e40968ce89de885d995937d5b85f24fa33a25df10990c5e11d5397199d779d5cf87d42f6627\",\"0c266fffe2ea2358fb93b5d30dfbcefe52a5bb53d6c85f37d54723613224a256165d20dd095768f168ab2e97bc5a879f7c2a84eee8963c9bcedcd39552dbe093\"]}";
    auto wj = json::parse(witness_json);
    P2PKWitness witness;
    from_json(wj, witness);
    REQUIRE(p2pk_ps->verify_witness(*secret, witness));
}

TEST_CASE("p2pk: post-locktime refund path valid (DotNut New_P2PkRules)", "[p2pk]") {
    // After locktime, refund path also valid with implicit n_sigs_refund=1
    std::string proof_json = "{\n  \"amount\": 64,\n  \"C\": \"02d7cd858d866fca404b5cb1ffd813946e6d19efa1af00d654080fd20266bdc0b1\",\n  \"id\": \"001b6c716bf42c7e\",\n  \"secret\": \"[\\\"P2PK\\\",{\\\"nonce\\\":\\\"395162bf2d0add3c66aea9f22c45251dbee6e04bd9282addbb366a94cd4fb482\\\",\\\"data\\\":\\\"03ab50a667926fac858bac540766254c14b2b0334d10e8ec766455310224bbecf4\\\",\\\"tags\\\":[[\\\"locktime\\\",\\\"21\\\"],[\\\"pubkeys\\\",\\\"0229a91adec8dd9badb228c628a07fc1bf707a9b7d95dd505c490b1766fa7dc541\\\",\\\"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e\\\"],[\\\"n_sigs\\\",\\\"2\\\"],[\\\"refund\\\",\\\"03ab50a667926fac858bac540766254c14b2b0334d10e8ec766455310224bbecf4\\\",\\\"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e\\\"]]}]\"\n}";
    auto j = json::parse(proof_json);
    std::string secret_str = j["secret"].get<std::string>();
    auto secret = parse_secret(secret_str);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    REQUIRE(nut10 != nullptr);
    auto* p2pk_ps = dynamic_cast<P2PKProofSecret*>(nut10->proof_secret().get());
    REQUIRE(p2pk_ps != nullptr);

    // Refund path witness with 1 sig (n_sigs_refund defaults to 1)
    std::string witness_json = "{\"signatures\":[\"d39631363480adf30433ee25c7cec28237e02b4808d4143469d4f390d4eae6ec97d18ba3cc6494ab1d04372f0838426ea296f25cb4bd8bddb296adc292eeaa96\"]}";
    auto wj = json::parse(witness_json);
    P2PKWitness witness;
    from_json(wj, witness);
    REQUIRE(p2pk_ps->verify_witness(*secret, witness));
}

// ============================================================
// NUT-11: P2PK dynamic build + sign + verify (DotNut Nut11_Signatures test A)
// ============================================================

TEST_CASE("p2pk: dynamic build sign verify with 3 keys (DotNut vector)", "[p2pk]") {
    // Exact keys from DotNut Nut11_Signatures
    PrivKey secretKey("99590802251e78ee1051648439eedb003dc539093a48a44e7b8f2642c909ea37");
    PrivKey signing_key_two("0000000000000000000000000000000000000000000000000000000000000001");
    PrivKey signing_key_three("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");

    // Build P2PK conditions: 2-of-2 multisig with locktime and refund
    P2PKBuilder conditions;
    conditions.lock = 21000000000;
    conditions.pubkeys = {signing_key_two.get_pub_key(), signing_key_three.get_pub_key()};
    conditions.refund_pubkeys = {secretKey.get_pub_key()};
    conditions.signature_threshold = 2;
    conditions.sig_flag = "SIG_INPUTS";

    auto ps = conditions.build();

    // Verify builder produced correct structure
    REQUIRE(ps.data == signing_key_two.get_pub_key().to_hex());
    REQUIRE(ps.tags.has_value());

    // Wrap in Nut10Secret
    auto secret_ptr = std::make_shared<P2PKProofSecret>(ps);
    Nut10Secret nut10_secret(P2PKProofSecret::KEY, secret_ptr);

    // Generate witness with signing keys
    auto msg = nut10_secret.get_bytes();
    auto witness_opt = ps.generate_witness(msg, {signing_key_two, signing_key_three});
    REQUIRE(witness_opt.has_value());
    REQUIRE(witness_opt->signatures.size() == 2);

    // Verify witness
    REQUIRE(ps.verify_witness(nut10_secret, witness_opt.value()));

    // Verify roundtrip through load
    auto loaded = P2PKBuilder::load(ps);
    REQUIRE(loaded.pubkeys.size() == 2);
    REQUIRE(loaded.pubkeys[0] == signing_key_two.get_pub_key());
    REQUIRE(loaded.pubkeys[1] == signing_key_three.get_pub_key());
    REQUIRE(loaded.signature_threshold == 2);
    REQUIRE(loaded.lock.value() == 21000000000);
    REQUIRE(loaded.refund_pubkeys.size() == 1);
    REQUIRE(loaded.refund_pubkeys[0] == secretKey.get_pub_key());
    REQUIRE(loaded.sig_flag == "SIG_INPUTS");
}

// ============================================================
// NUT-11: P2PK generate_witness + verify roundtrip
// ============================================================

TEST_CASE("p2pk: generate_witness and verify roundtrip", "[p2pk]") {
    PrivKey sk1("0000000000000000000000000000000000000000000000000000000000000001");
    PrivKey sk2("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");

    P2PKBuilder builder;
    builder.pubkeys = {sk1.get_pub_key(), sk2.get_pub_key()};
    builder.signature_threshold = 2;
    builder.sig_flag = "SIG_INPUTS";
    builder.nonce = "test_nonce_roundtrip";

    auto ps_base = builder.build();
    // Cast to P2PKProofSecret
    P2PKProofSecret ps;
    ps.nonce = ps_base.nonce;
    ps.data = ps_base.data;
    ps.tags = ps_base.tags;

    auto secret_ptr = std::make_shared<P2PKProofSecret>(ps);
    Nut10Secret nut10_secret(P2PKProofSecret::KEY, secret_ptr);

    auto msg = nut10_secret.get_bytes();
    auto witness_opt = ps.generate_witness(msg, {sk1, sk2});
    REQUIRE(witness_opt.has_value());
    REQUIRE(witness_opt->signatures.size() == 2);

    REQUIRE(ps.verify_witness(nut10_secret, witness_opt.value()));
}

TEST_CASE("p2pk: generate_witness single key", "[p2pk]") {
    PrivKey sk("99590802251e78ee1051648439eedb003dc539093a48a44e7b8f2642c909ea37");

    P2PKBuilder builder;
    builder.pubkeys = {sk.get_pub_key()};
    builder.nonce = "single_key_test";

    auto ps_base = builder.build();
    P2PKProofSecret ps;
    ps.nonce = ps_base.nonce;
    ps.data = ps_base.data;
    ps.tags = ps_base.tags;

    auto secret_ptr = std::make_shared<P2PKProofSecret>(ps);
    Nut10Secret nut10_secret(P2PKProofSecret::KEY, secret_ptr);

    auto msg = nut10_secret.get_bytes();
    auto witness_opt = ps.generate_witness(msg, {sk});
    REQUIRE(witness_opt.has_value());
    REQUIRE(witness_opt->signatures.size() == 1);

    REQUIRE(ps.verify_witness(nut10_secret, witness_opt.value()));

    // Wrong key should fail
    PrivKey wrong_sk("0000000000000000000000000000000000000000000000000000000000000001");
    P2PKWitness bad_witness;
    bad_witness.signatures = {"deadbeef"};
    REQUIRE_FALSE(ps.verify_witness(nut10_secret, bad_witness));
}

// ============================================================
// NUT-14: HTLC tests
// ============================================================

TEST_CASE("htlc: parse_secret creates HTLCProofSecret for HTLC key", "[htlc]") {
    // DotNut Nut14Tests_HTLCSecret vector
    std::string s = "[\"HTLC\",{\"nonce\":\"da62796403af76c80cd6ce9153ed3746\",\"data\":\"023192200a0cfd3867e48eb63b03ff599c7e46c8f4e41146b2d281173ca6c50c\",\"tags\":[[\"pubkeys\",\"02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904\"],[\"locktime\",\"1689418329\"],[\"refund\",\"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e\"]]}]";
    auto secret = parse_secret(s);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    REQUIRE(nut10 != nullptr);
    REQUIRE(nut10->key() == "HTLC");
    auto* htlc_ps = dynamic_cast<HTLCProofSecret*>(nut10->proof_secret().get());
    REQUIRE(htlc_ps != nullptr);
}

TEST_CASE("htlc: get_allowed_pubkeys from DotNut vector", "[htlc]") {
    std::string s = "[\"HTLC\",{\"nonce\":\"da62796403af76c80cd6ce9153ed3746\",\"data\":\"023192200a0cfd3867e48eb63b03ff599c7e46c8f4e41146b2d281173ca6c50c\",\"tags\":[[\"pubkeys\",\"02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904\"],[\"locktime\",\"1689418329\"],[\"refund\",\"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e\"]]}]";
    auto secret = parse_secret(s);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    REQUIRE(nut10 != nullptr);
    auto* htlc_ps = dynamic_cast<HTLCProofSecret*>(nut10->proof_secret().get());
    REQUIRE(htlc_ps != nullptr);

    int req_sigs = 0;
    auto pubkeys = htlc_ps->get_allowed_pubkeys(req_sigs);
    REQUIRE(pubkeys.size() == 1);
    REQUIRE(req_sigs == 1);
    REQUIRE(pubkeys[0].to_hex() == "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904");
}

TEST_CASE("htlc: HTLCBuilder build and load roundtrip (DotNut vector)", "[htlc]") {
    // Parse the DotNut vector
    std::string s = "[\"HTLC\",{\"nonce\":\"da62796403af76c80cd6ce9153ed3746\",\"data\":\"023192200a0cfd3867e48eb63b03ff599c7e46c8f4e41146b2d281173ca6c50c\",\"tags\":[[\"pubkeys\",\"02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904\"],[\"locktime\",\"1689418329\"],[\"refund\",\"033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e\"]]}]";
    auto secret = parse_secret(s);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    REQUIRE(nut10 != nullptr);
    auto* htlc_ps = dynamic_cast<HTLCProofSecret*>(nut10->proof_secret().get());
    REQUIRE(htlc_ps != nullptr);

    // Load into builder
    auto builder = HTLCBuilder::load(*htlc_ps);
    REQUIRE(builder.hashlock == "023192200a0cfd3867e48eb63b03ff599c7e46c8f4e41146b2d281173ca6c50c");
    REQUIRE(builder.pubkeys.size() == 1);
    REQUIRE(builder.pubkeys[0].to_hex() == "02698c4e2b5f9534cd0687d87513c759790cf829aa5739184a3e3735471fbda904");
    REQUIRE(builder.lock.value() == 1689418329);
    REQUIRE(builder.refund_pubkeys.size() == 1);
    REQUIRE(builder.refund_pubkeys[0].to_hex() == "033281c37677ea273eb7183b783067f5244933ef78d8c3f15b1a77cb246099c26e");

    // Rebuild and compare
    auto rebuilt = builder.build();
    auto rebuilt_ptr = std::make_shared<HTLCProofSecret>(rebuilt);
    Nut10Secret rebuilt_secret(HTLCProofSecret::KEY, rebuilt_ptr);
    auto original_bytes = secret->get_bytes();
    auto rebuilt_bytes = rebuilt_secret.get_bytes();

    // Parse both to compare structure (nonce differs so compare fields)
    REQUIRE(rebuilt.data == htlc_ps->data);
    REQUIRE(rebuilt.nonce == htlc_ps->nonce);
}

TEST_CASE("htlc: verify_preimage valid", "[htlc]") {
    std::string preimage_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    // SHA256(bytes[0x00..0x01]) = ec4916dd...
    std::string hashlock = "ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5";

    HTLCProofSecret ps;
    ps.data = hashlock;
    REQUIRE(ps.verify_preimage(preimage_hex));
}

TEST_CASE("htlc: verify_preimage invalid", "[htlc]") {
    HTLCProofSecret ps;
    ps.data = "ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5";
    REQUIRE_FALSE(ps.verify_preimage("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));
}

TEST_CASE("htlc: generate_witness and verify roundtrip", "[htlc]") {
    PrivKey sk("0000000000000000000000000000000000000000000000000000000000000001");
    std::string preimage_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    std::string hashlock = "ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5";

    // Build HTLC secret
    HTLCBuilder builder;
    builder.hashlock = hashlock;
    builder.pubkeys = {sk.get_pub_key()};
    builder.nonce = "htlc_test_nonce";

    auto ps = builder.build();
    auto secret_ptr = std::make_shared<HTLCProofSecret>(ps);
    Nut10Secret nut10_secret(HTLCProofSecret::KEY, secret_ptr);

    auto msg = nut10_secret.get_bytes();
    auto witness_opt = ps.generate_witness(msg, {sk}, preimage_hex);
    REQUIRE(witness_opt.has_value());
    REQUIRE(witness_opt->preimage.value() == preimage_hex);
    REQUIRE(witness_opt->signatures.size() == 1);

    // Verify
    REQUIRE(ps.verify_witness(nut10_secret, witness_opt.value()));
}

TEST_CASE("htlc: verify rejects P2PKWitness without preimage", "[htlc]") {
    PrivKey sk("0000000000000000000000000000000000000000000000000000000000000001");
    std::string preimage_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    std::string hashlock = "ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5";

    HTLCBuilder builder;
    builder.hashlock = hashlock;
    builder.pubkeys = {sk.get_pub_key()};
    builder.nonce = "htlc_reject_test";

    auto ps = builder.build();
    auto secret_ptr = std::make_shared<HTLCProofSecret>(ps);
    Nut10Secret nut10_secret(HTLCProofSecret::KEY, secret_ptr);

    // A P2PKWitness (not HTLCWitness) should be rejected
    P2PKWitness p2pk_witness;
    p2pk_witness.signatures = {"deadbeef"};
    REQUIRE_FALSE(ps.verify_witness(nut10_secret, p2pk_witness));
}

TEST_CASE("htlc: HTLCWitness JSON roundtrip", "[htlc]") {
    HTLCWitness w;
    w.preimage = "abcdef1234567890";
    w.signatures = {"sig1hex", "sig2hex"};

    json j;
    to_json(j, w);
    REQUIRE(j.contains("preimage"));
    REQUIRE(j["preimage"] == "abcdef1234567890");
    REQUIRE(j["signatures"].size() == 2);

    HTLCWitness w2;
    from_json(j, w2);
    REQUIRE(w2.preimage.value() == "abcdef1234567890");
    REQUIRE(w2.signatures.size() == 2);
}

TEST_CASE("htlc: HTLCWitness JSON without preimage", "[htlc]") {
    std::string witness_json = "{\"signatures\":[\"sig1\"]}";
    auto j = json::parse(witness_json);
    HTLCWitness w;
    from_json(j, w);
    REQUIRE_FALSE(w.preimage.has_value());
    REQUIRE(w.signatures.size() == 1);
}

TEST_CASE("htlc: HTLCBuilder validate rejects bad hashlock", "[htlc]") {
    HTLCBuilder builder;
    builder.hashlock = "tooshort";
    builder.pubkeys = {PubKey("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")};
    REQUIRE_THROWS_AS(builder.build(), std::invalid_argument);
}
