#pragma once

#include <cstdint>
#include <vector>
#include <utility>
#include "nutcpp/types/secret.h"
#include "nutcpp/types/priv_key.h"
#include "nutcpp/types/pub_key.h"
#include "nutcpp/types/keyset_id.h"
#include "nutcpp/types/keyset.h"
#include "nutcpp/types/blinded_message.h"
#include "nutcpp/types/blind_signature.h"
#include "nutcpp/types/proof.h"

namespace nutcpp::wallet {

// Blinding data for a single output: keeps secret and blinding factor paired
// so they can be matched with the mint's BlindSignature later.
struct BlindingData {
    StringSecret secret;
    PrivKey r;  // blinding factor

    BlindingData(const StringSecret& secret, const PrivKey& r)
        : secret(secret), r(r) {}
};

// Result of create_blinded_outputs: paired blinding data and blinded messages.
struct BlindedOutputs {
    std::vector<BlindingData> blinding_data;
    std::vector<BlindedMessage> blinded_messages;
};

// Power-of-2 decomposition of an amount.
// Example: split_amount(13) -> {1, 4, 8}
std::vector<uint64_t> split_amount(uint64_t amount);

// Create blinded outputs with random secrets and blinding factors (CSPRNG).
// For each amount: generates random secret, random r, computes Y = H(secret),
// B_ = Y + rG, and builds a BlindedMessage.
BlindedOutputs create_blinded_outputs(const std::vector<uint64_t>& amounts,
                                      const KeysetId& keyset_id);

// Create blinded outputs with pre-generated secrets and blinding factors.
// For NUT-13 deterministic derivation: caller provides secrets and r values.
// secrets.size() and blinding_factors.size() must equal amounts.size().
BlindedOutputs create_blinded_outputs(const std::vector<uint64_t>& amounts,
                                      const KeysetId& keyset_id,
                                      const std::vector<StringSecret>& secrets,
                                      const std::vector<PrivKey>& blinding_factors);

// Unblind signatures from the mint to produce Proofs.
// For each BlindSignature: looks up public key A from keyset by amount,
// computes C = C_ - rA, and constructs a Proof.
// signatures.size() must equal blinding_data.size().
std::vector<Proof> unblind_signatures(const std::vector<BlindSignature>& signatures,
                                      const std::vector<BlindingData>& blinding_data,
                                      const Keyset& keyset);

} // namespace nutcpp::wallet
