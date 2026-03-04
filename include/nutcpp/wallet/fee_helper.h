#pragma once

#include <cstdint>
#include <vector>
#include <map>
#include "nutcpp/types/proof.h"
#include "nutcpp/types/keyset_id.h"

namespace nutcpp::wallet {

/// Compute the total fee (in sat) for a set of proofs given per-keyset PPK fees.
/// Formula: (sum_ppk + 999) / 1000  (ceiling division, NUT-02/08)
uint64_t compute_fee(const std::vector<Proof>& proofs,
                     const std::map<KeysetId, uint64_t>& keyset_fees);

} // namespace nutcpp::wallet
