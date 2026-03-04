#include "nutcpp/wallet/fee_helper.h"

namespace nutcpp::wallet {

uint64_t compute_fee(const std::vector<Proof>& proofs,
                     const std::map<KeysetId, uint64_t>& keyset_fees) {
    uint64_t sum = 0;
    for (const auto& proof : proofs) {
        auto it = keyset_fees.find(proof.id);
        if (it != keyset_fees.end()) {
            sum += it->second;
        }
    }
    return (sum + 999) / 1000;
}

} // namespace nutcpp::wallet
