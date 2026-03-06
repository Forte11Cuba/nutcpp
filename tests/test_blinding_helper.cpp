#include <catch2/catch_test_macros.hpp>
#include "nutcpp/wallet/blinding_helper.h"
#include "nutcpp/crypto/cashu.h"
#include "nutcpp/types/priv_key.h"
#include <set>
#include <algorithm>

using namespace nutcpp;
using namespace nutcpp::wallet;

// ============================================================
// split_amount tests
// ============================================================

TEST_CASE("split_amount: 0 returns empty", "[wallet][blinding]") {
    auto result = split_amount(0);
    REQUIRE(result.empty());
}

TEST_CASE("split_amount: power of 2", "[wallet][blinding]") {
    auto result = split_amount(64);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0] == 64);
}

TEST_CASE("split_amount: 13 = 1+4+8", "[wallet][blinding]") {
    auto result = split_amount(13);
    REQUIRE(result.size() == 3);
    // Sorted ascending (LSB first)
    REQUIRE(result[0] == 1);
    REQUIRE(result[1] == 4);
    REQUIRE(result[2] == 8);
    // Verify sum
    uint64_t sum = 0;
    for (auto v : result) sum += v;
    REQUIRE(sum == 13);
}

TEST_CASE("split_amount: 100 = 4+32+64", "[wallet][blinding]") {
    auto result = split_amount(100);
    REQUIRE(result.size() == 3);
    uint64_t sum = 0;
    for (auto v : result) sum += v;
    REQUIRE(sum == 100);
    // Each element is a power of 2
    for (auto v : result) {
        REQUIRE((v & (v - 1)) == 0);
        REQUIRE(v > 0);
    }
}

TEST_CASE("split_amount: 1 returns {1}", "[wallet][blinding]") {
    auto result = split_amount(1);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0] == 1);
}

TEST_CASE("split_amount: 255 = all bits set", "[wallet][blinding]") {
    auto result = split_amount(255);
    REQUIRE(result.size() == 8);
    uint64_t sum = 0;
    for (auto v : result) sum += v;
    REQUIRE(sum == 255);
}

TEST_CASE("split_amount: 1023", "[wallet][blinding]") {
    auto result = split_amount(1023);
    REQUIRE(result.size() == 10);
    uint64_t sum = 0;
    for (auto v : result) sum += v;
    REQUIRE(sum == 1023);
}

TEST_CASE("split_amount: large value 2^20", "[wallet][blinding]") {
    auto result = split_amount(1048576);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0] == 1048576);
}

// ============================================================
// create_blinded_outputs (random) tests
// ============================================================

TEST_CASE("create_blinded_outputs: random, correct count and structure", "[wallet][blinding]") {
    KeysetId kid("00abcdef01234567");
    std::vector<uint64_t> amounts = {1, 4, 8};

    auto outputs = create_blinded_outputs(amounts, kid);

    REQUIRE(outputs.blinding_data.size() == 3);
    REQUIRE(outputs.blinded_messages.size() == 3);

    for (size_t i = 0; i < 3; ++i) {
        CHECK(outputs.blinded_messages[i].amount == amounts[i]);
        CHECK(outputs.blinded_messages[i].id == kid);
        // Secret is 64 hex chars (32 bytes)
        CHECK(outputs.blinding_data[i].secret.value().size() == 64);
    }
}

TEST_CASE("create_blinded_outputs: random secrets are unique", "[wallet][blinding]") {
    KeysetId kid("00abcdef01234567");
    std::vector<uint64_t> amounts = {1, 2, 4, 8, 16};

    auto outputs = create_blinded_outputs(amounts, kid);

    std::set<std::string> secrets;
    for (const auto& bd : outputs.blinding_data) {
        secrets.insert(bd.secret.value());
    }
    REQUIRE(secrets.size() == amounts.size());
}

TEST_CASE("create_blinded_outputs: B_ is reproducible from secret and r", "[wallet][blinding]") {
    KeysetId kid("00abcdef01234567");
    std::vector<uint64_t> amounts = {64};

    auto outputs = create_blinded_outputs(amounts, kid);

    // Recompute B_ from the returned secret and r
    PubKey Y = outputs.blinding_data[0].secret.to_curve();
    PubKey B_expected = crypto::compute_B_(Y, outputs.blinding_data[0].r);

    REQUIRE(outputs.blinded_messages[0].B_.to_hex() == B_expected.to_hex());
}

TEST_CASE("create_blinded_outputs: empty amounts returns empty", "[wallet][blinding]") {
    KeysetId kid("00abcdef01234567");
    auto outputs = create_blinded_outputs({}, kid);
    REQUIRE(outputs.blinding_data.empty());
    REQUIRE(outputs.blinded_messages.empty());
}

// ============================================================
// create_blinded_outputs (deterministic, NUT-13) tests
// ============================================================

TEST_CASE("create_blinded_outputs: deterministic with known secret and r", "[wallet][blinding]") {
    KeysetId kid("00abcdef01234567");
    std::vector<uint64_t> amounts = {1, 2};

    // Use fixed known values
    StringSecret s1("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    StringSecret s2("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    PrivKey r1("0000000000000000000000000000000000000000000000000000000000000001");
    PrivKey r2("0000000000000000000000000000000000000000000000000000000000000002");

    auto outputs = create_blinded_outputs(amounts, kid, {s1, s2}, {r1, r2});

    REQUIRE(outputs.blinding_data.size() == 2);
    REQUIRE(outputs.blinded_messages.size() == 2);

    // Verify secret and r are preserved
    CHECK(outputs.blinding_data[0].secret.value() == s1.value());
    CHECK(outputs.blinding_data[1].secret.value() == s2.value());
    CHECK(outputs.blinding_data[0].r.to_hex() == r1.to_hex());
    CHECK(outputs.blinding_data[1].r.to_hex() == r2.to_hex());

    // Verify B_ is computed correctly
    PubKey Y1 = s1.to_curve();
    PubKey B1_expected = crypto::compute_B_(Y1, r1);
    CHECK(outputs.blinded_messages[0].B_.to_hex() == B1_expected.to_hex());
}

TEST_CASE("create_blinded_outputs: deterministic mismatched secrets throws", "[wallet][blinding]") {
    KeysetId kid("00abcdef01234567");
    std::vector<uint64_t> amounts = {1, 2};
    StringSecret s1("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    PrivKey r1("0000000000000000000000000000000000000000000000000000000000000001");
    PrivKey r2("0000000000000000000000000000000000000000000000000000000000000002");

    // 1 secret but 2 amounts
    REQUIRE_THROWS_AS(
        create_blinded_outputs(amounts, kid, {s1}, {r1, r2}),
        std::invalid_argument);
}

TEST_CASE("create_blinded_outputs: deterministic mismatched blinding_factors throws", "[wallet][blinding]") {
    KeysetId kid("00abcdef01234567");
    std::vector<uint64_t> amounts = {1, 2};
    StringSecret s1("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    StringSecret s2("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    PrivKey r1("0000000000000000000000000000000000000000000000000000000000000001");

    // 2 secrets but 1 r
    REQUIRE_THROWS_AS(
        create_blinded_outputs(amounts, kid, {s1, s2}, {r1}),
        std::invalid_argument);
}

// ============================================================
// unblind_signatures tests
// ============================================================

// Full BDHKE roundtrip: create outputs, simulate mint signing, unblind
TEST_CASE("unblind_signatures: full BDHKE roundtrip", "[wallet][blinding]") {
    // Mint's private key for amount 1
    PrivKey mint_key("0000000000000000000000000000000000000000000000000000000000000001");
    PubKey mint_pub = mint_key.get_pub_key();

    // Build a keyset with one denomination
    KeysetId kid("00abcdef01234567");
    Keyset keyset;
    keyset.emplace(1, mint_pub);

    // Wallet creates blinded output
    StringSecret secret("test_secret_for_roundtrip_verification_padding!");
    PrivKey r("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");

    auto outputs = create_blinded_outputs({1}, kid, {secret}, {r});
    REQUIRE(outputs.blinded_messages.size() == 1);

    // Mint signs: C_ = k * B_
    PubKey C_ = crypto::compute_C_(outputs.blinded_messages[0].B_, mint_key);
    BlindSignature sig(1, kid, C_);

    // Wallet unblinds
    auto proofs = unblind_signatures({sig}, outputs.blinding_data, keyset);

    REQUIRE(proofs.size() == 1);
    CHECK(proofs[0].amount == 1);
    CHECK(proofs[0].id == kid);
    CHECK(proofs[0].secret == secret.value());

    // Verify: C should equal k * Y (where Y = H(secret))
    PubKey Y = secret.to_curve();
    PubKey C_expected = crypto::compute_C_(Y, mint_key);
    CHECK(proofs[0].C.to_hex() == C_expected.to_hex());
}

TEST_CASE("unblind_signatures: mismatched sizes throws", "[wallet][blinding]") {
    Keyset keyset;
    KeysetId kid("00abcdef01234567");
    PrivKey mint_key("0000000000000000000000000000000000000000000000000000000000000001");
    keyset.emplace(1, mint_key.get_pub_key());

    BlindSignature sig(1, kid, mint_key.get_pub_key());  // dummy C_
    StringSecret secret("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    PrivKey r("0000000000000000000000000000000000000000000000000000000000000001");

    // 1 signature but 0 blinding data
    REQUIRE_THROWS_AS(
        unblind_signatures({sig}, {}, keyset),
        std::invalid_argument);
}

TEST_CASE("unblind_signatures: missing keyset amount throws", "[wallet][blinding]") {
    Keyset keyset;
    KeysetId kid("00abcdef01234567");
    PrivKey mint_key("0000000000000000000000000000000000000000000000000000000000000001");
    // Keyset only has amount 1
    keyset.emplace(1, mint_key.get_pub_key());

    // Signature for amount 2 (not in keyset)
    BlindSignature sig(2, kid, mint_key.get_pub_key());
    StringSecret secret("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    PrivKey r("0000000000000000000000000000000000000000000000000000000000000001");
    BlindingData bd(secret, r);

    REQUIRE_THROWS_AS(
        unblind_signatures({sig}, {bd}, keyset),
        std::runtime_error);
}

TEST_CASE("unblind_signatures: empty inputs returns empty", "[wallet][blinding]") {
    Keyset keyset;
    auto proofs = unblind_signatures({}, {}, keyset);
    REQUIRE(proofs.empty());
}

TEST_CASE("unblind_signatures: preserves DLEQ from signature", "[wallet][blinding]") {
    PrivKey mint_key("0000000000000000000000000000000000000000000000000000000000000001");
    PubKey mint_pub = mint_key.get_pub_key();

    KeysetId kid("00abcdef01234567");
    Keyset keyset;
    keyset.emplace(1, mint_pub);

    StringSecret secret("test_dleq_preservation_secret_padding_for_length!");
    PrivKey r("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");

    auto outputs = create_blinded_outputs({1}, kid, {secret}, {r});
    PubKey C_ = crypto::compute_C_(outputs.blinded_messages[0].B_, mint_key);

    // Create signature with DLEQ proof
    PrivKey e_val("1111111111111111111111111111111111111111111111111111111111111111");
    PrivKey s_val("2222222222222222222222222222222222222222222222222222222222222222");
    DLEQProof dleq(e_val, s_val, r);
    BlindSignature sig(1, kid, C_, dleq);

    auto proofs = unblind_signatures({sig}, outputs.blinding_data, keyset);

    REQUIRE(proofs.size() == 1);
    REQUIRE(proofs[0].dleq.has_value());
    CHECK(proofs[0].dleq->e.to_hex() == e_val.to_hex());
    CHECK(proofs[0].dleq->s.to_hex() == s_val.to_hex());
}

TEST_CASE("unblind_signatures: multiple denominations", "[wallet][blinding]") {
    PrivKey k1("0000000000000000000000000000000000000000000000000000000000000001");
    PrivKey k2("0000000000000000000000000000000000000000000000000000000000000002");
    PrivKey k4("0000000000000000000000000000000000000000000000000000000000000003");

    KeysetId kid("00abcdef01234567");
    Keyset keyset;
    keyset.emplace(1, k1.get_pub_key());
    keyset.emplace(2, k2.get_pub_key());
    keyset.emplace(4, k4.get_pub_key());

    std::vector<uint64_t> amounts = {1, 2, 4};
    StringSecret s1("secret_one_padded_to_be_long_enough_for_construction");
    StringSecret s2("secret_two_padded_to_be_long_enough_for_construction");
    StringSecret s3("secret_thr_padded_to_be_long_enough_for_construction");
    PrivKey r1("1111111111111111111111111111111111111111111111111111111111111111");
    PrivKey r2("2222222222222222222222222222222222222222222222222222222222222222");
    PrivKey r3("3333333333333333333333333333333333333333333333333333333333333333");

    auto outputs = create_blinded_outputs(amounts, kid, {s1, s2, s3}, {r1, r2, r3});

    // Mint signs each with the corresponding key
    std::vector<BlindSignature> sigs;
    PrivKey mint_keys[] = {k1, k2, k4};
    for (size_t i = 0; i < 3; ++i) {
        PubKey C_ = crypto::compute_C_(outputs.blinded_messages[i].B_, mint_keys[i]);
        sigs.emplace_back(amounts[i], kid, C_);
    }

    auto proofs = unblind_signatures(sigs, outputs.blinding_data, keyset);

    REQUIRE(proofs.size() == 3);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(proofs[i].amount == amounts[i]);
        CHECK(proofs[i].id == kid);

        // Verify each C = k * Y
        PubKey Y = outputs.blinding_data[i].secret.to_curve();
        PubKey C_expected = crypto::compute_C_(Y, mint_keys[i]);
        CHECK(proofs[i].C.to_hex() == C_expected.to_hex());
    }
}

// ============================================================
// End-to-end: split_amount + create + unblind
// ============================================================

TEST_CASE("end-to-end: split_amount + create_blinded_outputs + unblind_signatures", "[wallet][blinding]") {
    // Mint keys for denominations 4, 32, 64
    PrivKey k4("0000000000000000000000000000000000000000000000000000000000000004");
    PrivKey k32("0000000000000000000000000000000000000000000000000000000000000020");
    PrivKey k64("0000000000000000000000000000000000000000000000000000000000000040");

    KeysetId kid("00abcdef01234567");
    Keyset keyset;
    keyset.emplace(4, k4.get_pub_key());
    keyset.emplace(32, k32.get_pub_key());
    keyset.emplace(64, k64.get_pub_key());

    // Step 1: split
    auto amounts = split_amount(100);  // {4, 32, 64}
    REQUIRE(amounts.size() == 3);
    uint64_t sum = 0;
    for (auto a : amounts) sum += a;
    REQUIRE(sum == 100);

    // Step 2: create blinded outputs (random)
    auto outputs = create_blinded_outputs(amounts, kid);
    REQUIRE(outputs.blinded_messages.size() == amounts.size());

    // Step 3: mint signs each
    std::vector<BlindSignature> sigs;
    for (size_t i = 0; i < amounts.size(); ++i) {
        PrivKey* mk = nullptr;
        if (amounts[i] == 4) mk = &k4;
        else if (amounts[i] == 32) mk = &k32;
        else if (amounts[i] == 64) mk = &k64;
        REQUIRE(mk != nullptr);
        PubKey C_ = crypto::compute_C_(outputs.blinded_messages[i].B_, *mk);
        sigs.emplace_back(amounts[i], kid, C_);
    }

    // Step 4: unblind
    auto proofs = unblind_signatures(sigs, outputs.blinding_data, keyset);

    REQUIRE(proofs.size() == amounts.size());
    uint64_t proof_sum = 0;
    for (const auto& p : proofs) {
        proof_sum += p.amount;
        CHECK(p.id == kid);
        CHECK(!p.secret.empty());
    }
    REQUIRE(proof_sum == 100);
}
