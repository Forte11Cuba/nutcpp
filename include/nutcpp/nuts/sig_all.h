#pragma once

#include <string>
#include <vector>
#include <optional>
#include "nutcpp/types/proof.h"
#include "nutcpp/types/blinded_message.h"
#include "nutcpp/nuts/p2pk.h"

namespace nutcpp {

// NUT-11 SIG_ALL: Construct the message to sign for a SIG_ALL transaction.
// msg = secret_0 || C_0 || ... || secret_n || C_n || amount_0 || B_0 || ... || amount_m || B_m [|| quote_id]
// Throws invalid_argument if inputs/outputs are empty, first proof lacks SIG_ALL flag,
// or proofs have different data/tags.
std::string get_message_to_sign(
    const std::vector<Proof>& inputs,
    const std::vector<BlindedMessage>& outputs,
    const std::optional<std::string>& melt_quote_id = std::nullopt);

// Verify SIG_ALL witness with explicit witness object.
// Supports both P2PKWitness and HTLCWitness (via polymorphic reference).
bool verify_sig_all_witness(
    const std::vector<Proof>& proofs,
    const std::vector<BlindedMessage>& outputs,
    const P2PKWitness& witness,
    const std::optional<std::string>& melt_quote_id = std::nullopt);

// Verify SIG_ALL witness extracted from first proof's witness field.
bool verify_sig_all_witness(
    const std::vector<Proof>& proofs,
    const std::vector<BlindedMessage>& outputs,
    const std::optional<std::string>& melt_quote_id = std::nullopt);

} // namespace nutcpp
