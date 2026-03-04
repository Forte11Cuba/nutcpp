#include <catch2/catch_test_macros.hpp>
#include "nutcpp/wallet/fee_helper.h"
#include "nutcpp/types/priv_key.h"
#include <sstream>
#include <iomanip>

using namespace nutcpp;
using namespace nutcpp::wallet;

// Helper: generate a unique Proof with a deterministic PubKey derived from index
static Proof make_proof(uint64_t amount, const KeysetId& kid, uint32_t index) {
    // Build a 32-byte private key from index (zero-padded)
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(64) << std::hex << index;
    PrivKey sk(oss.str());
    PubKey C = sk.get_pub_key();
    return Proof(amount, kid, "secret_" + std::to_string(index), C);
}

// ============================================================
// FeeHelper tests
// ============================================================

TEST_CASE("fee_helper: empty proofs returns 0", "[wallet]") {
    std::map<KeysetId, uint64_t> fees;
    REQUIRE(compute_fee({}, fees) == 0);
}

TEST_CASE("fee_helper: single proof 100 ppk gives fee 1", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 100}};
    auto p = make_proof(64, kid, 1);
    REQUIRE(compute_fee({p}, fees) == 1);
}

TEST_CASE("fee_helper: 0 ppk gives fee 0", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 0}};
    auto p = make_proof(64, kid, 1);
    REQUIRE(compute_fee({p}, fees) == 0);
}

TEST_CASE("fee_helper: 10 proofs x 100 ppk = 1000 ppk gives fee 1", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 100}};
    std::vector<Proof> proofs;
    for (uint32_t i = 1; i <= 10; ++i)
        proofs.push_back(make_proof(8, kid, i));
    REQUIRE(compute_fee(proofs, fees) == 1);
}

TEST_CASE("fee_helper: 11 proofs x 100 ppk = 1100 ppk gives fee 2", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 100}};
    std::vector<Proof> proofs;
    for (uint32_t i = 1; i <= 11; ++i)
        proofs.push_back(make_proof(8, kid, i));
    REQUIRE(compute_fee(proofs, fees) == 2);
}

TEST_CASE("fee_helper: 1 ppk gives fee 1 (minimum non-zero)", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 1}};
    auto p = make_proof(64, kid, 1);
    REQUIRE(compute_fee({p}, fees) == 1);
}

TEST_CASE("fee_helper: 999 ppk gives fee 1", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 999}};
    auto p = make_proof(64, kid, 1);
    REQUIRE(compute_fee({p}, fees) == 1);
}

TEST_CASE("fee_helper: keyset not in map gives fee 0", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    KeysetId other("00ffffff01234567");
    std::map<KeysetId, uint64_t> fees{{other, 100}};
    auto p = make_proof(64, kid, 1);
    REQUIRE(compute_fee({p}, fees) == 0);
}

TEST_CASE("fee_helper: mixed keysets with different fees", "[wallet]") {
    KeysetId kid_a("00abcdef01234567");
    KeysetId kid_b("00ffffff01234567");
    std::map<KeysetId, uint64_t> fees{{kid_a, 100}, {kid_b, 200}};
    auto p1 = make_proof(64, kid_a, 1);
    auto p2 = make_proof(32, kid_b, 2);
    // sum = 100 + 200 = 300 → (300 + 999) / 1000 = 1
    REQUIRE(compute_fee({p1, p2}, fees) == 1);
}

TEST_CASE("fee_helper: NUT-02 spec example (3 proofs, 100 ppk)", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 100}};
    std::vector<Proof> proofs;
    for (uint32_t i = 1; i <= 3; ++i)
        proofs.push_back(make_proof(16, kid, i));
    // sum = 300 → (300 + 999) / 1000 = 1
    REQUIRE(compute_fee(proofs, fees) == 1);
}

TEST_CASE("fee_helper: 100 proofs x 100 ppk gives fee 10", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 100}};
    std::vector<Proof> proofs;
    for (uint32_t i = 1; i <= 100; ++i)
        proofs.push_back(make_proof(4, kid, i));
    // sum = 10000 → (10000 + 999) / 1000 = 10
    REQUIRE(compute_fee(proofs, fees) == 10);
}

TEST_CASE("fee_helper: all keysets unknown gives fee 0", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees; // empty
    std::vector<Proof> proofs;
    for (uint32_t i = 1; i <= 5; ++i)
        proofs.push_back(make_proof(8, kid, i));
    REQUIRE(compute_fee(proofs, fees) == 0);
}
