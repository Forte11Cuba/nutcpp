#include <catch2/catch_test_macros.hpp>
#include "nutcpp/crypto/cashu.h"
#include "nutcpp/encoding/convert_utils.h"

using namespace nutcpp;
using namespace nutcpp::crypto;

// ============================================================
// NUT-00: hash_to_curve
// Official test vectors from nuts/tests/00-tests.md
// ============================================================

TEST_CASE("hash_to_curve test vector 1", "[crypto]") {
    auto Y = hex_to_curve("0000000000000000000000000000000000000000000000000000000000000000");
    REQUIRE(Y.to_hex() == "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725");
}

TEST_CASE("hash_to_curve test vector 2", "[crypto]") {
    auto Y = hex_to_curve("0000000000000000000000000000000000000000000000000000000000000001");
    REQUIRE(Y.to_hex() == "022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf");
}

TEST_CASE("hash_to_curve test vector 3 (multiple iterations)", "[crypto]") {
    auto Y = hex_to_curve("0000000000000000000000000000000000000000000000000000000000000002");
    REQUIRE(Y.to_hex() == "026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f");
}

// ============================================================
// NUT-00: Blinded messages (B_ = Y + rG)
// Official test vectors from nuts/tests/00-tests.md
// ============================================================

TEST_CASE("Blinded message test vector 1", "[crypto]") {
    auto Y = hex_to_curve("d341ee4871f1f889041e63cf0d3823c713eea6aff01e80f1719f08f9e5be98f6");
    PrivKey r("99fce58439fc37412ab3468b73db0569322588f62fb3a49182d67e23d877824a");
    auto B_ = compute_B_(Y, r);
    REQUIRE(B_.to_hex() == "033b1a9737a40cc3fd9b6af4b723632b76a67a36782596304612a6c2bfb5197e6d");
}

TEST_CASE("Blinded message test vector 2", "[crypto]") {
    auto Y = hex_to_curve("f1aaf16c2239746f369572c0784d9dd3d032d952c2d992175873fb58fae31a60");
    PrivKey r("f78476ea7cc9ade20f9e05e58a804cf19533f03ea805ece5fee88c8e2874ba50");
    auto B_ = compute_B_(Y, r);
    REQUIRE(B_.to_hex() == "029bdf2d716ee366eddf599ba252786c1033f47e230248a4612a5670ab931f1763");
}

// ============================================================
// NUT-00: Blinded signatures (C_ = kB_)
// Official test vectors from nuts/tests/00-tests.md
// ============================================================

TEST_CASE("Blinded signature test vector 1 (k=1)", "[crypto]") {
    PrivKey k("0000000000000000000000000000000000000000000000000000000000000001");
    PubKey B_("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
    auto C_ = compute_C_(B_, k);
    // k=1, so C_ = 1*B_ = B_
    REQUIRE(C_.to_hex() == "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
}

TEST_CASE("Blinded signature test vector 2", "[crypto]") {
    PrivKey k("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
    PubKey B_("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
    auto C_ = compute_C_(B_, k);
    REQUIRE(C_.to_hex() == "0398bc70ce8184d27ba89834d19f5199c84443c31131e48d3c1214db24247d005d");
}

// ============================================================
// NUT-00: Full BDHKE roundtrip
// ============================================================

TEST_CASE("BDHKE full roundtrip", "[crypto]") {
    // Alice: generate Y from secret, blind with r
    auto Y = hex_to_curve("d341ee4871f1f889041e63cf0d3823c713eea6aff01e80f1719f08f9e5be98f6");
    PrivKey r("99fce58439fc37412ab3468b73db0569322588f62fb3a49182d67e23d877824a");
    auto B_ = compute_B_(Y, r);

    // Bob: sign with private key k
    PrivKey k("0000000000000000000000000000000000000000000000000000000000000001");
    auto C_ = compute_C_(B_, k);

    // Alice: unblind to get C = C_ - rA
    PubKey A = k.get_pub_key(); // A = kG
    auto C = compute_C(C_, r, A);

    // C should be a valid point (compressed hex, 66 chars, starts with 02 or 03)
    auto hex = C.to_hex();
    REQUIRE(hex.size() == 66);
    REQUIRE((hex.substr(0, 2) == "02" || hex.substr(0, 2) == "03"));

    // Verify determinism: same inputs produce same C
    auto C2 = compute_C(compute_C_(compute_B_(Y, r), k), r, A);
    REQUIRE(C == C2);
}

// ============================================================
// NUT-12: hash_e function
// Official test vector from nuts/tests/12-tests.md
// ============================================================

TEST_CASE("hash_e test vector", "[crypto]") {
    PubKey R1("020000000000000000000000000000000000000000000000000000000000000001");
    PubKey R2("020000000000000000000000000000000000000000000000000000000000000001");
    PubKey K("020000000000000000000000000000000000000000000000000000000000000001");
    PubKey C_("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");

    PrivKey e = compute_e(R1, R2, K, C_);
    REQUIRE(e.to_hex() == "a4dc034b74338c28c6bc3ea49731f2a24440fc7c4affc08b31a93fc9fbe6401e");
}

// ============================================================
// NUT-12: DLEQ verification on BlindSignature
// Official test vector from nuts/tests/12-tests.md
// ============================================================

TEST_CASE("DLEQ verify BlindSignature", "[crypto]") {
    PubKey A("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    PubKey B_("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
    PubKey C_("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
    PrivKey e("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9");
    PrivKey s("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da");

    REQUIRE(verify_proof(B_, C_, e, s, A));
}

// ============================================================
// NUT-12: DLEQ verification on Proof
// Official test vector from nuts/tests/12-tests.md
// ============================================================

TEST_CASE("DLEQ verify Proof", "[crypto]") {
    PubKey A("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    std::string secret = "daf4dd00a2b68a0858a80450f52c8a7d2ccf87d375e43e216e0c571f089f63e9";
    PubKey C("024369d2d22a80ecf78f3937da9d5f30c1b9f74f0c32684d583cca0fa6a61cdcfc");
    PrivKey e("b31e58ac6527f34975ffab13e70a48b6d2b0d35abc4b03f0151f09ee1a9763d4");
    PrivKey s("8fbae004c59e754d71df67e392b6ae4e29293113ddc2ec86592a0431d16306d8");
    PrivKey r("a6d13fcd7a18442e6076f5e1e7c887ad5de40a019824bdfa9fe740d302e8d861");

    // Y = hash_to_curve of the secret as UTF-8 bytes (not hex-decoded)
    // In Cashu, StringSecret.ToCurve() hashes the UTF-8 string directly
    PubKey Y = message_to_curve(secret);

    REQUIRE(verify_proof(Y, r, C, e, s, A));
}

// ============================================================
// NUT-12: compute_proof + verify_proof roundtrip
// ============================================================

TEST_CASE("DLEQ compute and verify roundtrip", "[crypto]") {
    // Use known values
    auto Y = hex_to_curve("d341ee4871f1f889041e63cf0d3823c713eea6aff01e80f1719f08f9e5be98f6");
    PrivKey r("99fce58439fc37412ab3468b73db0569322588f62fb3a49182d67e23d877824a");
    auto B_ = compute_B_(Y, r);

    // Mint private key
    PrivKey a("0000000000000000000000000000000000000000000000000000000000000001");
    // Random nonce for proof
    PrivKey p("0000000000000000000000000000000000000000000000000000000000000002");

    // Bob computes proof
    auto [e, s] = compute_proof(B_, a, p);

    // Verify proof on BlindSignature
    PubKey A = a.get_pub_key();
    auto C_ = compute_C_(B_, a);
    REQUIRE(verify_proof(B_, C_, e, s, A));

    // Verify proof on Proof (after unblinding)
    auto C = compute_C(C_, r, A);
    REQUIRE(verify_proof(Y, r, C, e, s, A));
}

// ============================================================
// NUT-12: Invalid proof should fail
// ============================================================

TEST_CASE("DLEQ invalid proof fails verification", "[crypto]") {
    PubKey A("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    PubKey B_("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
    PubKey C_("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
    // Valid e but tampered s (last byte changed)
    PrivKey e("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9");
    PrivKey s("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73ff");

    REQUIRE_FALSE(verify_proof(B_, C_, e, s, A));
}
