#pragma once

#include <vector>
#include <optional>
#include <utility>
#include "nutcpp/types/pub_key.h"
#include "nutcpp/types/priv_key.h"
#include "nutcpp/nuts/p2pk.h"

namespace nutcpp {

// ============================================================
// NUT-28 P2BK: Core crypto functions
// ============================================================

// Compute ECDH shared x-coordinate: Zx = x(e * P) = x(p * E)
// Returns 32-byte x-only coordinate.
std::vector<unsigned char> compute_zx(const PrivKey& e, const PubKey& P);

// Compute deterministic blinding scalar for slot i:
// ri = SHA256("Cashu_P2BK_v1" || Zx || i_byte)
// Retries with 0xff suffix if result is not a valid scalar.
PrivKey compute_ri(const std::vector<unsigned char>& Zx, int i);

// Blind a public key: P' = P + r*G
PubKey compute_blinded_key(const PubKey& P, const PrivKey& r);

// ============================================================
// NUT-28 P2BK: Builder
// ============================================================

// Build a P2PKProofSecret with blinded pubkeys using ephemeral key e.
// Blinds all pubkeys in slot order [data, ...pubkeys, ...refund] before calling build().
P2PKProofSecret build_blinded(P2PKBuilder builder, const PrivKey& e);

// Build with random ephemeral key. Returns (proof_secret, E).
std::pair<P2PKProofSecret, PubKey> build_blinded(P2PKBuilder builder);

// ============================================================
// NUT-28 P2BK: Blind witness generation
// ============================================================

// Sign using derived (blinded) private keys.
// Receiver computes Zx = p*E, derives ri, then signs with (p + ri) or (-p + ri).
std::optional<P2PKWitness> generate_blind_witness(
    const P2PKProofSecret& ps,
    const std::vector<unsigned char>& msg,
    const std::vector<PrivKey>& keys,
    const PubKey& E);

} // namespace nutcpp
