#include <catch2/catch_test_macros.hpp>
#include "nutcpp/wallet/fee_helper.h"
#include "nutcpp/wallet/proof_selector.h"
#include "nutcpp/types/priv_key.h"
#include <sstream>
#include <iomanip>
#include <set>
#include <chrono>

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

// ============================================================
// ProofSelector tests
// ============================================================

// Helper: sum amounts in a proof vector
static uint64_t sum_amounts(const std::vector<Proof>& proofs) {
    uint64_t s = 0;
    for (const auto& p : proofs) s += p.amount;
    return s;
}

TEST_CASE("proof_selector: exact amount without fees", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 0}};
    // Proofs: 1, 2, 4, 8, 16, 32, 64
    std::vector<Proof> proofs;
    uint32_t idx = 1;
    for (uint64_t a : {1, 2, 4, 8, 16, 32, 64})
        proofs.push_back(make_proof(a, kid, idx++));

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 21);
    REQUIRE(sum_amounts(res.send) >= 21);
    REQUIRE(sum_amounts(res.send) + sum_amounts(res.keep) == 127);
}

TEST_CASE("proof_selector: amount equals total balance", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 0}};
    std::vector<Proof> proofs;
    for (uint32_t i = 1; i <= 4; ++i)
        proofs.push_back(make_proof(8, kid, i));

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 32);
    REQUIRE(res.send.size() == 4);
    REQUIRE(res.keep.empty());
}

TEST_CASE("proof_selector: amount 0 returns empty send", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 0}};
    std::vector<Proof> proofs;
    proofs.push_back(make_proof(8, kid, 1));

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 0);
    REQUIRE(res.send.empty());
    REQUIRE(res.keep.size() == 1);
}

TEST_CASE("proof_selector: amount > total returns empty send", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 0}};
    std::vector<Proof> proofs;
    proofs.push_back(make_proof(8, kid, 1));

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 100);
    REQUIRE(res.send.empty());
    REQUIRE(res.keep.size() == 1);
}

TEST_CASE("proof_selector: single proof exact match", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 0}};
    std::vector<Proof> proofs;
    proofs.push_back(make_proof(64, kid, 1));

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 64);
    REQUIRE(res.send.size() == 1);
    REQUIRE(res.send[0].amount == 64);
    REQUIRE(res.keep.empty());
}

TEST_CASE("proof_selector: empty proofs returns empty send", "[wallet]") {
    std::map<KeysetId, uint64_t> fees;
    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send({}, 10);
    REQUIRE(res.send.empty());
    REQUIRE(res.keep.empty());
}

TEST_CASE("proof_selector: include_fees subtracts effective value", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 1000}}; // 1 sat fee per proof
    std::vector<Proof> proofs;
    // 3 proofs of 10 sat each. With fees: effective = 10 - 1 = 9 each.
    for (uint32_t i = 1; i <= 3; ++i)
        proofs.push_back(make_proof(10, kid, i));

    ProofSelector sel(fees);
    // Need 18 sat net. 2 proofs: 20 amount - 2 fee = 18 net. Exact.
    auto res = sel.select_proofs_to_send(proofs, 18, true);
    REQUIRE(sum_amounts(res.send) >= 18);
    // Net value of send must cover 18
    uint64_t send_fee = compute_fee(res.send, fees);
    REQUIRE(sum_amounts(res.send) - send_fee >= 18);
}

TEST_CASE("proof_selector: uneconomical proofs filtered", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    // Fee = 1000 ppk = 1 sat/proof. A 1-sat proof has exFee = 0 → filtered.
    std::map<KeysetId, uint64_t> fees{{kid, 1000}};
    std::vector<Proof> proofs;
    proofs.push_back(make_proof(1, kid, 1));  // uneconomical
    proofs.push_back(make_proof(8, kid, 2));  // ok: 8 - 1 = 7

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 5, true);
    REQUIRE(res.send.size() == 1);
    REQUIRE(res.send[0].amount == 8);
}

TEST_CASE("proof_selector: fees make total insufficient", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    // Fee = 5000 ppk = 5 sat/proof. Proof of 4 has exFee = -1 → filtered.
    std::map<KeysetId, uint64_t> fees{{kid, 5000}};
    std::vector<Proof> proofs;
    proofs.push_back(make_proof(4, kid, 1));

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 1, true);
    REQUIRE(res.send.empty());
}

TEST_CASE("proof_selector: mixed keysets with different fees", "[wallet]") {
    KeysetId kid_a("00abcdef01234567");
    KeysetId kid_b("00ffffff01234567");
    std::map<KeysetId, uint64_t> fees{{kid_a, 100}, {kid_b, 200}};
    std::vector<Proof> proofs;
    proofs.push_back(make_proof(16, kid_a, 1));
    proofs.push_back(make_proof(32, kid_b, 2));
    proofs.push_back(make_proof(8, kid_a, 3));

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 30);
    REQUIRE(sum_amounts(res.send) >= 30);
    REQUIRE(sum_amounts(res.send) + sum_amounts(res.keep) == 56);
}

TEST_CASE("proof_selector: keep + send == original (invariant)", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 100}};
    std::vector<Proof> proofs;
    for (uint32_t i = 1; i <= 10; ++i)
        proofs.push_back(make_proof(1 << (i % 6), kid, i));

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 15);
    REQUIRE(res.send.size() + res.keep.size() == proofs.size());
    REQUIRE(sum_amounts(res.send) + sum_amounts(res.keep) == sum_amounts(proofs));
}

TEST_CASE("proof_selector: send >= amount_to_send (invariant)", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 0}};
    std::vector<Proof> proofs;
    for (uint32_t i = 1; i <= 8; ++i)
        proofs.push_back(make_proof(i * 3, kid, i));

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 25);
    REQUIRE(!res.send.empty());
    REQUIRE(sum_amounts(res.send) >= 25);
}

TEST_CASE("proof_selector: no proof in both keep and send", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 0}};
    std::vector<Proof> proofs;
    for (uint32_t i = 1; i <= 6; ++i)
        proofs.push_back(make_proof(8, kid, i));

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 20);

    std::set<PubKey> send_cs, keep_cs;
    for (const auto& p : res.send) send_cs.insert(p.C);
    for (const auto& p : res.keep) keep_cs.insert(p.C);

    for (const auto& c : send_cs)
        REQUIRE(keep_cs.find(c) == keep_cs.end());
}

TEST_CASE("proof_selector: many proofs same denomination", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 0}};
    std::vector<Proof> proofs;
    for (uint32_t i = 1; i <= 20; ++i)
        proofs.push_back(make_proof(4, kid, i));

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 28);
    REQUIRE(sum_amounts(res.send) >= 28);
    // Optimal: 7 proofs of 4 = 28 exact
    REQUIRE(sum_amounts(res.send) == 28);
}

TEST_CASE("proof_selector: power-of-2 denominations (standard Cashu)", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 0}};
    std::vector<Proof> proofs;
    uint32_t idx = 1;
    for (uint64_t a : {1, 2, 4, 8, 16, 32, 64, 128})
        proofs.push_back(make_proof(a, kid, idx++));

    ProofSelector sel(fees);
    // 42 = 32 + 8 + 2
    auto res = sel.select_proofs_to_send(proofs, 42);
    REQUIRE(sum_amounts(res.send) >= 42);
    REQUIRE(sum_amounts(res.send) + sum_amounts(res.keep) == 255);
}

TEST_CASE("proof_selector: unknown keysets with include_fees treats ppk as 0", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees; // empty — kid not found
    std::vector<Proof> proofs;
    proofs.push_back(make_proof(16, kid, 1));
    proofs.push_back(make_proof(8, kid, 2));

    ProofSelector sel(fees);
    auto res = sel.select_proofs_to_send(proofs, 10, true);
    REQUIRE(sum_amounts(res.send) >= 10);
}

TEST_CASE("proof_selector: performance with 500 proofs", "[wallet]") {
    KeysetId kid("00abcdef01234567");
    std::map<KeysetId, uint64_t> fees{{kid, 100}};
    std::vector<Proof> proofs;
    for (uint32_t i = 1; i <= 500; ++i)
        proofs.push_back(make_proof((i % 7) + 1, kid, i));

    ProofSelector sel(fees);
    auto t0 = std::chrono::steady_clock::now();
    auto res = sel.select_proofs_to_send(proofs, 100, true);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    REQUIRE(sum_amounts(res.send) >= 100);
    REQUIRE(elapsed < 5000); // generous limit — typically < 1s
}
