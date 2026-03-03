#pragma once

#include <vector>
#include <string>
#include <utility>
#include <cstdint>
#include "nutcpp/types/pub_key.h"
#include "nutcpp/types/priv_key.h"

namespace nutcpp {
namespace crypto {

// ============================================================
// NUT-00: Hash to curve
// ============================================================

// Deterministically maps bytes to a point on secp256k1.
// Y = PubKey('02' || SHA256(msg_hash || counter))
// where msg_hash = SHA256(DOMAIN_SEPARATOR || x)
PubKey hash_to_curve(const std::vector<unsigned char>& x);

// Convenience: hex string -> bytes -> hash_to_curve
PubKey hex_to_curve(const std::string& hex);

// Convenience: UTF-8 string -> bytes -> hash_to_curve
PubKey message_to_curve(const std::string& message);

// ============================================================
// NUT-00: Blind Diffie-Hellman key exchange (BDHKE)
// ============================================================

// Blinding: B_ = Y + rG
PubKey compute_B_(const PubKey& Y, const PrivKey& r);

// Signing: C_ = kB_
PubKey compute_C_(const PubKey& B_, const PrivKey& k);

// Unblinding: C = C_ - rA
PubKey compute_C(const PubKey& C_, const PrivKey& r, const PubKey& A);

// ============================================================
// NUT-12: DLEQ proofs
// ============================================================

// Hash function for DLEQ: SHA256 of concatenated uncompressed pubkey hex strings.
// e = SHA256(R1_uncompressed_hex || R2_uncompressed_hex || K_uncompressed_hex || C__uncompressed_hex)
PrivKey compute_e(const PubKey& R1, const PubKey& R2, const PubKey& K, const PubKey& C_);

// Generate DLEQ proof. Returns (e, s).
// Bob proves he used the same private key 'a' for A=aG and C_=aB_.
// 'p' is a random nonce.
std::pair<PrivKey, PrivKey> compute_proof(const PubKey& B_, const PrivKey& a, const PrivKey& p);

// Verify DLEQ proof on BlindSignature (Alice verifies Bob's signature).
// Checks: R1 = sG - eA, R2 = sB_ - eC_, e == hash(R1, R2, A, C_)
bool verify_proof(const PubKey& B_, const PubKey& C_, const PrivKey& e, const PrivKey& s, const PubKey& A);

// Verify DLEQ proof on Proof (Carol verifies received token).
// Reconstructs B_ = Y + rG and C_ = C + rA, then calls verify_proof above.
bool verify_proof(const PubKey& Y, const PrivKey& r, const PubKey& C, const PrivKey& e, const PrivKey& s, const PubKey& A);

} // namespace crypto
} // namespace nutcpp
