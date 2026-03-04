#include "nutcpp/nuts/htlc.h"
#include "nutcpp/encoding/convert_utils.h"
#include "../crypto/sha256.h"

#include <stdexcept>
#include <algorithm>
#include <chrono>

using namespace std;

namespace nutcpp {

// ============================================================
// Dummy pubkey for HTLCBuilder (reuse P2PKBuilder tag parsing)
// ============================================================

static PubKey get_dummy_pubkey() {
    static PubKey dummy("020000000000000000000000000000000000000000000000000000000000000001");
    return dummy;
}

// ============================================================
// HTLCBuilder
// ============================================================

HTLCProofSecret HTLCBuilder::build() const {
    if (hashlock.size() != 64 ||
        !all_of(hashlock.begin(), hashlock.end(), ::isxdigit))
        throw invalid_argument("HTLCBuilder: hashlock must be 64 hex chars");

    // Validate threshold against real pubkeys (before dummy injection)
    if (static_cast<int>(pubkeys.size()) < signature_threshold)
        throw invalid_argument("HTLCBuilder: signature threshold exceeds pubkey count");

    // Use dummy pubkey trick: prepend dummy to pubkeys so P2PKBuilder
    // puts it in the data field, then replace with hashlock
    P2PKBuilder inner;
    inner.pubkeys = {get_dummy_pubkey()};
    for (const auto& pk : pubkeys)
        inner.pubkeys.push_back(pk);
    inner.lock = lock;
    inner.refund_pubkeys = refund_pubkeys;
    inner.signature_threshold = signature_threshold;
    inner.sig_flag = sig_flag;
    inner.nonce = nonce;
    inner.refund_signature_threshold = refund_signature_threshold;

    auto base = inner.build();

    HTLCProofSecret result;
    result.data = hashlock;  // replace dummy with hashlock
    result.nonce = base.nonce;
    result.tags = base.tags;
    return result;
}

HTLCBuilder HTLCBuilder::load(const Nut10ProofSecret& ps) {
    // Extract hashlock from data field
    string hashlock_val = ps.data;

    // Create temp proof secret with dummy pubkey so P2PKBuilder::load can parse tags
    Nut10ProofSecret temp;
    temp.data = get_dummy_pubkey().to_hex();
    temp.nonce = ps.nonce;
    temp.tags = ps.tags;

    auto inner = P2PKBuilder::load(temp);

    // Remove dummy pubkey from position 0 (where build() injected it)
    vector<PubKey> real_pubkeys;
    if (!inner.pubkeys.empty())
        real_pubkeys.assign(inner.pubkeys.begin() + 1, inner.pubkeys.end());

    HTLCBuilder result;
    result.hashlock = hashlock_val;
    result.pubkeys = move(real_pubkeys);
    result.lock = inner.lock;
    result.refund_pubkeys = inner.refund_pubkeys;
    result.signature_threshold = inner.signature_threshold;
    result.sig_flag = inner.sig_flag;
    result.nonce = inner.nonce;
    result.refund_signature_threshold = inner.refund_signature_threshold;
    return result;
}

// ============================================================
// HTLCProofSecret
// ============================================================

vector<PubKey> HTLCProofSecret::get_allowed_pubkeys(int& required_sigs) const {
    auto builder = HTLCBuilder::load(*this);
    required_sigs = builder.signature_threshold;
    return builder.pubkeys;
}

vector<PubKey> HTLCProofSecret::get_allowed_refund_pubkeys(optional<int>& required_sigs) const {
    auto builder = HTLCBuilder::load(*this);

    if (!builder.lock.has_value() || builder.lock.value() >= chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()).count()) {
        required_sigs = nullopt;
        return {};
    }

    if (builder.refund_pubkeys.empty()) {
        required_sigs = 0;
        return {};
    }

    required_sigs = builder.refund_signature_threshold.value_or(1);
    return builder.refund_pubkeys;
}

bool HTLCProofSecret::verify_preimage(const string& preimage_hex) const {
    try {
        auto preimage_bytes = hex_to_bytes(preimage_hex);
        auto hash = internal::SHA256::hash(preimage_bytes.data(), preimage_bytes.size());
        string hash_hex = bytes_to_hex(hash.data(), hash.size());
        return hash_hex == data;
    } catch (...) {
        return false;  // malformed hex → invalid preimage
    }
}

optional<HTLCWitness> HTLCProofSecret::generate_witness(
    const vector<unsigned char>& msg, const vector<PrivKey>& keys,
    const string& preimage_hex) const
{
    if (!verify_preimage(preimage_hex))
        throw runtime_error("HTLCProofSecret: invalid preimage");

    // Delegate signature generation to P2PK base
    auto p2pk_witness = P2PKProofSecret::generate_witness(msg, keys);
    if (!p2pk_witness.has_value())
        return nullopt;

    HTLCWitness result;
    result.preimage = preimage_hex;
    result.signatures = move(p2pk_witness->signatures);
    return result;
}

bool HTLCProofSecret::verify_witness_hash(const unsigned char hash[32], const P2PKWitness& witness) const {
    // Must be an HTLCWitness
    auto* htlc_witness = dynamic_cast<const HTLCWitness*>(&witness);
    if (!htlc_witness)
        return false;

    // Verify preimage against hashlock
    if (!htlc_witness->preimage.has_value() || !verify_preimage(htlc_witness->preimage.value()))
        return false;

    // Delegate signature verification to P2PK base
    return P2PKProofSecret::verify_witness_hash(hash, witness);
}

} // namespace nutcpp
