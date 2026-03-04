#include "nutcpp/nuts/sig_all.h"
#include "nutcpp/nuts/nut10_secret.h"
#include "nutcpp/nuts/htlc.h"

#include <stdexcept>

using namespace std;

namespace nutcpp {

// ============================================================
// Internal helpers
// ============================================================

// Validate that first proof has SIG_ALL flag. Returns proof_secret or nullptr.
static shared_ptr<Nut10ProofSecret> validate_first_proof(const Proof& first_proof) {
    auto secret = parse_secret(first_proof.secret);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    if (!nut10)
        return nullptr;

    auto ps = nut10->proof_secret();

    // Dispatch to appropriate builder to check sigflag
    string sig_flag;
    auto* htlc_ps = dynamic_cast<HTLCProofSecret*>(ps.get());
    if (htlc_ps) {
        auto builder = HTLCBuilder::load(*htlc_ps);
        sig_flag = builder.sig_flag;
    } else {
        auto* p2pk_ps = dynamic_cast<P2PKProofSecret*>(ps.get());
        if (p2pk_ps) {
            auto builder = P2PKBuilder::load(*p2pk_ps);
            sig_flag = builder.sig_flag;
        }
    }

    if (sig_flag != "SIG_ALL")
        return nullptr;

    return ps;
}

// Compare only data and tags (not nonce) — per spec, SIG_ALL requires
// identical data and tags across all inputs, but nonces differ per proof.
static bool same_data_and_tags(const Nut10ProofSecret& a, const Nut10ProofSecret& b) {
    return a.data == b.data && a.tags == b.tags;
}

// ============================================================
// get_message_to_sign
// ============================================================

string get_message_to_sign(
    const vector<Proof>& inputs,
    const vector<BlindedMessage>& outputs,
    const optional<string>& melt_quote_id)
{
    if (inputs.empty())
        throw invalid_argument("At least one proof is required for SIG_ALL.");
    if (outputs.empty())
        throw invalid_argument("At least one blinded output is required for SIG_ALL.");

    auto first_secret = validate_first_proof(inputs[0]);
    if (!first_secret)
        throw invalid_argument("Provided first proof is invalid");

    string msg;

    for (const auto& p : inputs) {
        auto secret = parse_secret(p.secret);
        auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
        if (!nut10)
            throw invalid_argument("When signing sig_all, every proof must be a nut 10 secret.");

        if (!same_data_and_tags(*nut10->proof_secret(), *first_secret))
            throw invalid_argument("When signing sig_all, every proof must have identical tags and data.");

        msg += p.secret;
        msg += p.C.to_hex();
    }

    for (const auto& b : outputs) {
        msg += to_string(b.amount);
        msg += b.B_.to_hex();
    }

    if (melt_quote_id.has_value())
        msg += melt_quote_id.value();

    return msg;
}

// ============================================================
// verify_sig_all_witness (explicit witness)
// ============================================================

bool verify_sig_all_witness(
    const vector<Proof>& proofs,
    const vector<BlindedMessage>& outputs,
    const P2PKWitness& witness,
    const optional<string>& melt_quote_id)
{
    if (proofs.empty())
        return false;

    string msg_str;
    try {
        msg_str = get_message_to_sign(proofs, outputs, melt_quote_id);
    } catch (...) {
        return false;
    }

    vector<unsigned char> msg(msg_str.begin(), msg_str.end());

    auto secret = parse_secret(proofs[0].secret);
    auto* nut10 = dynamic_cast<Nut10Secret*>(secret.get());
    if (!nut10)
        return false;

    auto ps = nut10->proof_secret();

    auto* htlc_ps = dynamic_cast<HTLCProofSecret*>(ps.get());
    if (htlc_ps)
        return htlc_ps->verify_witness(msg, witness);

    auto* p2pk_ps = dynamic_cast<P2PKProofSecret*>(ps.get());
    if (p2pk_ps)
        return p2pk_ps->verify_witness(msg, witness);

    return false;
}

// ============================================================
// verify_sig_all_witness (extract from first proof)
// ============================================================

bool verify_sig_all_witness(
    const vector<Proof>& proofs,
    const vector<BlindedMessage>& outputs,
    const optional<string>& melt_quote_id)
{
    if (proofs.empty())
        return false;

    if (!proofs[0].witness.has_value())
        return false;

    // Try HTLC first (has preimage), fall back to P2PK
    try {
        auto j = nlohmann::json::parse(proofs[0].witness.value());

        if (j.contains("preimage") && !j["preimage"].is_null()) {
            HTLCWitness htlc_w = j.get<HTLCWitness>();
            return verify_sig_all_witness(proofs, outputs, htlc_w, melt_quote_id);
        }

        P2PKWitness p2pk_w = j.get<P2PKWitness>();
        return verify_sig_all_witness(proofs, outputs, p2pk_w, melt_quote_id);
    } catch (...) {
        return false;
    }
}

} // namespace nutcpp
