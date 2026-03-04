#include "nutcpp/wallet/proof_selector.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>
#include <random>
#include <set>

namespace nutcpp::wallet {

// ── Internal types & helpers ────────────────────────────────────────

namespace {

struct ProofWithFee {
    const Proof* proof;   // non-owning — input vector outlives this
    double ex_fee;        // effective value (amount minus fee share)
    uint64_t ppk_fee;     // per-proof-per-thousand fee for this keyset
};

constexpr int    MAX_TRIALS = 60;
constexpr long   MAX_TIMEMS = 1000;
constexpr int    MAX_P2SWAP = 5000;
constexpr double MAX_OVRPCT = 0;
constexpr uint64_t MAX_OVRAMT = 0;
constexpr bool   EXACT_MATCH = false;

// Net amount after fees
double sum_ex_fees(uint64_t amount, uint64_t fee_ppk, bool include_fees) {
    return amount - (include_fees ? std::ceil(fee_ppk / 1000.0) : 0);
}

// Delta: excess over target. Lower is better. Infinity = invalid.
double calculate_delta(uint64_t amount, uint64_t fee_ppk,
                       uint64_t amount_to_send, bool include_fees) {
    double net = sum_ex_fees(amount, fee_ppk, include_fees);
    if (net < amount_to_send)
        return std::numeric_limits<double>::infinity();
    return amount + fee_ppk / 1000.0 - amount_to_send;
}

// Binary search on sorted (ASC by ex_fee) vector.
// less_or_equal=true  → rightmost index where ex_fee <= value
// less_or_equal=false → leftmost index where ex_fee >= value
// Returns -1 if not found.
int binary_search_index(const std::vector<ProofWithFee>& arr,
                        double value, bool less_or_equal) {
    int left = 0;
    int right = static_cast<int>(arr.size()) - 1;
    int result = -1;

    while (left <= right) {
        int mid = (left + right) / 2;
        double mid_val = arr[mid].ex_fee;

        if (less_or_equal ? (mid_val <= value) : (mid_val >= value)) {
            result = mid;
            if (less_or_equal)
                left = mid + 1;
            else
                right = mid - 1;
        } else {
            if (less_or_equal)
                right = mid - 1;
            else
                left = mid + 1;
        }
    }

    if (!less_or_equal && result == -1 && left < static_cast<int>(arr.size()))
        return left;

    return result;
}

// Insert keeping sorted order by ex_fee ASC.
void insert_sorted(std::vector<ProofWithFee>& arr, const ProofWithFee& obj) {
    double value = obj.ex_fee;
    int left = 0;
    int right = static_cast<int>(arr.size());

    while (left < right) {
        int mid = (left + right) / 2;
        if (arr[mid].ex_fee < value)
            left = mid + 1;
        else
            right = mid;
    }
    arr.insert(arr.begin() + left, obj);
}

} // anonymous namespace

// ── ProofSelector implementation ────────────────────────────────────

ProofSelector::ProofSelector(const std::map<KeysetId, uint64_t>& keyset_fees)
    : keyset_fees_(keyset_fees) {}

uint64_t ProofSelector::get_proof_fee_ppk(const Proof& proof) const {
    auto it = keyset_fees_.find(proof.id);
    return it != keyset_fees_.end() ? it->second : 0;
}

SendResponse ProofSelector::select_proofs_to_send(
    const std::vector<Proof>& proofs,
    uint64_t amount_to_send,
    bool include_fees) const {

    auto start_time = std::chrono::steady_clock::now();

    std::vector<ProofWithFee>* best_subset = nullptr;
    double best_delta = std::numeric_limits<double>::infinity();
    uint64_t best_amount = 0;
    uint64_t best_fee_ppk = 0;

    // ── Pre-processing ──────────────────────────────────────────

    uint64_t total_amount = 0;
    uint64_t total_fee_ppk = 0;

    std::vector<ProofWithFee> proof_with_fees;
    proof_with_fees.reserve(proofs.size());

    for (const auto& p : proofs) {
        uint64_t ppk = get_proof_fee_ppk(p);
        double ex = include_fees ? p.amount - ppk / 1000.0 : p.amount;
        proof_with_fees.push_back({&p, ex, ppk});

        if (!include_fees || ex > 0) {
            total_amount += p.amount;
            total_fee_ppk += ppk;
        }
    }

    // Filter uneconomical proofs
    std::vector<ProofWithFee> spendable;
    if (include_fees) {
        for (auto& pwf : proof_with_fees) {
            if (pwf.ex_fee > 0)
                spendable.push_back(pwf);
        }
    } else {
        spendable = proof_with_fees;
    }

    // Sort by ex_fee ASC
    std::sort(spendable.begin(), spendable.end(),
              [](const ProofWithFee& a, const ProofWithFee& b) {
                  return a.ex_fee < b.ex_fee;
              });

    // Remove proofs too large to be useful
    if (!spendable.empty()) {
        int end_index;
        if (EXACT_MATCH) {
            int ri = binary_search_index(spendable, static_cast<double>(amount_to_send), true);
            end_index = ri >= 0 ? ri + 1 : 0;
        } else {
            int bi = binary_search_index(spendable, static_cast<double>(amount_to_send), false);
            if (bi >= 0) {
                double next_bigger = spendable[bi].ex_fee;
                int ri = binary_search_index(spendable, next_bigger, true);
                end_index = ri >= 0 ? ri + 1 : static_cast<int>(spendable.size());
            } else {
                end_index = static_cast<int>(spendable.size());
            }
        }

        // Adjust totals for removed proofs
        for (int i = end_index; i < static_cast<int>(spendable.size()); ++i) {
            total_amount -= spendable[i].proof->amount;
            total_fee_ppk -= spendable[i].ppk_fee;
        }
        spendable.resize(end_index);
    }

    // Validate
    double total_net = sum_ex_fees(total_amount, total_fee_ppk, include_fees);
    if (amount_to_send == 0 || amount_to_send > total_net) {
        return {proofs, {}};
    }

    // Max acceptable overage
    double max_over = std::min(
        std::ceil(amount_to_send * (1.0 + MAX_OVRPCT / 100.0)),
        std::min(static_cast<double>(amount_to_send + MAX_OVRAMT), total_net));

    // ── RGLI Loop ───────────────────────────────────────────────

    std::mt19937 rng(std::random_device{}());
    std::vector<ProofWithFee> owned_best; // storage for best_subset

    for (int trial = 0; trial < MAX_TRIALS; ++trial) {

        // PHASE 1: Randomized Greedy Selection
        std::vector<ProofWithFee> S;
        uint64_t amount = 0;
        uint64_t fee_ppk = 0;

        {
            std::vector<ProofWithFee> shuffled = spendable;
            std::shuffle(shuffled.begin(), shuffled.end(), rng);

            for (auto& obj : shuffled) {
                uint64_t new_amount = amount + obj.proof->amount;
                uint64_t new_fee = fee_ppk + obj.ppk_fee;
                double net = sum_ex_fees(new_amount, new_fee, include_fees);

                if (EXACT_MATCH && net > amount_to_send)
                    break;

                S.push_back(obj);
                amount = new_amount;
                fee_ppk = new_fee;

                if (net >= amount_to_send)
                    break;
            }
        }

        // PHASE 2: Local Improvement
        // Build "others" — spendable proofs not in S
        std::set<PubKey> selected_cs;
        for (const auto& pwf : S)
            selected_cs.insert(pwf.proof->C);

        std::vector<ProofWithFee> others;
        for (const auto& obj : spendable) {
            if (selected_cs.find(obj.proof->C) == selected_cs.end())
                others.push_back(obj);
        }

        // Random order for swap indices
        std::vector<int> indices(S.size());
        std::iota(indices.begin(), indices.end(), 0);
        std::shuffle(indices.begin(), indices.end(), rng);
        if (static_cast<int>(indices.size()) > MAX_P2SWAP)
            indices.resize(MAX_P2SWAP);

        for (int i : indices) {
            double net = sum_ex_fees(amount, fee_ppk, include_fees);
            if (std::abs(net - amount_to_send) < 0.0001 ||
                (!EXACT_MATCH && net >= amount_to_send && net <= max_over)) {
                break;
            }

            auto& obj_p = S[i];
            uint64_t temp_amount = amount - obj_p.proof->amount;
            uint64_t temp_fee = fee_ppk - obj_p.ppk_fee;
            double temp_net = sum_ex_fees(temp_amount, temp_fee, include_fees);
            double target = amount_to_send - temp_net;

            int q_idx = binary_search_index(others, target, EXACT_MATCH);
            if (q_idx >= 0) {
                auto& obj_q = others[q_idx];
                if (!EXACT_MATCH || obj_q.ex_fee > obj_p.ex_fee) {
                    if (target >= 0 || obj_q.ex_fee <= obj_p.ex_fee) {
                        auto old_p = obj_p;
                        S[i] = obj_q;
                        amount = temp_amount + obj_q.proof->amount;
                        fee_ppk = temp_fee + obj_q.ppk_fee;
                        others.erase(others.begin() + q_idx);
                        insert_sorted(others, old_p);
                    }
                }
            }
        }

        // Update best solution
        double delta = calculate_delta(amount, fee_ppk, amount_to_send, include_fees);
        if (delta < best_delta) {
            // Copy & sort by ex_fee DESC
            owned_best = S;
            std::sort(owned_best.begin(), owned_best.end(),
                      [](const ProofWithFee& a, const ProofWithFee& b) {
                          return a.ex_fee > b.ex_fee;
                      });
            best_subset = &owned_best;
            best_delta = delta;
            best_amount = amount;
            best_fee_ppk = fee_ppk;

            // PHASE 3: Refinement — try removing smallest proofs
            std::vector<ProofWithFee> temp_s = owned_best;
            while (temp_s.size() > 1 && best_delta > 0) {
                auto obj_p = temp_s.back();
                temp_s.pop_back();

                uint64_t ta = amount - obj_p.proof->amount;
                uint64_t tf = fee_ppk - obj_p.ppk_fee;
                double td = calculate_delta(ta, tf, amount_to_send, include_fees);

                if (std::isinf(td))
                    break;

                if (td < best_delta) {
                    owned_best = temp_s;
                    best_subset = &owned_best;
                    best_delta = td;
                    best_amount = ta;
                    best_fee_ppk = tf;
                    amount = ta;
                    fee_ppk = tf;
                }
            }
        }

        // Check if solution is acceptable
        if (best_subset && !std::isinf(best_delta)) {
            double best_net = sum_ex_fees(best_amount, best_fee_ppk, include_fees);
            if (std::abs(best_net - amount_to_send) < 0.0001 ||
                (!EXACT_MATCH && best_net >= amount_to_send && best_net <= max_over)) {
                break;
            }
        }

        // Time limit
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time).count();
        if (elapsed > MAX_TIMEMS)
            break;
    }

    // ── Build result ────────────────────────────────────────────

    if (best_subset && !std::isinf(best_delta)) {
        std::set<PubKey> send_cs;
        std::vector<Proof> send;
        for (const auto& pwf : *best_subset) {
            send_cs.insert(pwf.proof->C);
            send.push_back(*pwf.proof);
        }

        std::vector<Proof> keep;
        for (const auto& p : proofs) {
            if (send_cs.find(p.C) == send_cs.end())
                keep.push_back(p);
        }

        return {keep, send};
    }

    return {proofs, {}};
}

} // namespace nutcpp::wallet
