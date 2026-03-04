#pragma once

#include <cstdint>
#include <vector>
#include <map>
#include "nutcpp/types/proof.h"
#include "nutcpp/types/keyset_id.h"

namespace nutcpp::wallet {

struct SendResponse {
    std::vector<Proof> keep;
    std::vector<Proof> send;
};

class ProofSelector {
public:
    explicit ProofSelector(const std::map<KeysetId, uint64_t>& keyset_fees);

    SendResponse select_proofs_to_send(const std::vector<Proof>& proofs,
                                       uint64_t amount_to_send,
                                       bool include_fees = false) const;

private:
    std::map<KeysetId, uint64_t> keyset_fees_;

    uint64_t get_proof_fee_ppk(const Proof& proof) const;
};

} // namespace nutcpp::wallet
