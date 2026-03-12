#include "nutcpp/nuts/p2bk.h"
#include "nutcpp/encoding/convert_utils.h"
#include "../crypto/sha256.h"

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <cstring>
#include <stdexcept>
#include <set>
#include "../crypto/secure_zero.h"

#ifdef __linux__
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#endif

using namespace std;

namespace nutcpp {

// ============================================================
// Internal helpers (same pattern as p2pk.cpp, static linkage)
// ============================================================

static void fill_random(unsigned char* buf, size_t len) {
#ifdef __linux__
    ssize_t ret = getrandom(buf, len, 0);
    if (ret < 0 || static_cast<size_t>(ret) != len)
        throw runtime_error("getrandom() failed");
#elif defined(__APPLE__)
    if (SecRandomCopyBytes(kSecRandomDefault, len, buf) != errSecSuccess)
        throw runtime_error("SecRandomCopyBytes() failed");
#elif defined(_WIN32)
    if (BCryptGenRandom(NULL, buf, static_cast<ULONG>(len),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw runtime_error("BCryptGenRandom() failed");
#else
    #error "No secure random source available for this platform"
#endif
}

static secp256k1_context* get_context() {
    static secp256k1_context* ctx = []() {
        auto c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (!c) throw runtime_error("secp256k1_context_create failed");
        unsigned char seed[32];
        fill_random(seed, 32);
        if (!secp256k1_context_randomize(c, seed)) {
            secp256k1_context_destroy(c);
            throw runtime_error("secp256k1_context_randomize failed");
        }
        return c;
    }();
    return ctx;
}

// BIP-340 Schnorr sign: msg must be 32 bytes. Returns hex sig (128 chars).
static string schnorr_sign(const unsigned char msg[32], const PrivKey& privkey) {
    auto ctx = get_context();
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ctx, &keypair, privkey.data()))
        throw runtime_error("secp256k1_keypair_create failed");

    unsigned char aux[32];
    fill_random(aux, 32);

    unsigned char sig[64];
    if (!secp256k1_schnorrsig_sign32(ctx, sig, msg, &keypair, aux))
        throw runtime_error("secp256k1_schnorrsig_sign32 failed");

    return bytes_to_hex(sig, 64);
}

// ============================================================
// NUT-28 P2BK: Core crypto functions
// ============================================================

vector<unsigned char> compute_zx(const PrivKey& e, const PubKey& P) {
    auto ctx = get_context();

    // Copy pubkey (tweak_mul modifies in-place)
    secp256k1_pubkey pk = P.get();

    // pk = e * pk  (ECDH point multiplication)
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &pk, e.data()))
        throw runtime_error("secp256k1_ec_pubkey_tweak_mul failed");

    // Extract x-only coordinate (32 bytes)
    secp256k1_xonly_pubkey xonly;
    int parity;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, &parity, &pk))
        throw runtime_error("secp256k1_xonly_pubkey_from_pubkey failed");

    unsigned char output[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, output, &xonly))
        throw runtime_error("secp256k1_xonly_pubkey_serialize failed");

    return vector<unsigned char>(output, output + 32);
}

PrivKey compute_ri(const vector<unsigned char>& Zx, int i) {
    static const string prefix = "Cashu_P2BK_v1";
    unsigned char i_byte = static_cast<unsigned char>(i & 0xFF);

    // SHA256("Cashu_P2BK_v1" || Zx || i_byte)
    internal::SHA256 hasher;
    hasher.update(prefix);
    hasher.update(Zx);
    hasher.update(&i_byte, 1);
    auto hash = hasher.finalize();

    // Validate as scalar
    auto ctx = get_context();
    if (secp256k1_ec_seckey_verify(ctx, hash.data()))
        return PrivKey(hash.data());

    // Retry with 0xff suffix
    internal::SHA256 hasher2;
    hasher2.update(prefix);
    hasher2.update(Zx);
    hasher2.update(&i_byte, 1);
    unsigned char ff = 0xff;
    hasher2.update(&ff, 1);
    hash = hasher2.finalize();

    return PrivKey(hash.data());
}

PubKey compute_blinded_key(const PubKey& P, const PrivKey& r) {
    auto ctx = get_context();

    // Copy pubkey (tweak_add modifies in-place)
    secp256k1_pubkey pk = P.get();

    // P' = P + r*G
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &pk, r.data()))
        throw runtime_error("secp256k1_ec_pubkey_tweak_add failed");

    return PubKey(pk);
}

// ============================================================
// NUT-28 P2BK: Builder
// ============================================================

P2PKProofSecret build_blinded(P2PKBuilder builder, const PrivKey& e) {
    int n_normal = static_cast<int>(builder.pubkeys.size());
    int n_refund = static_cast<int>(builder.refund_pubkeys.size());

    // Blind normal pubkeys (slots 0..n_normal-1)
    for (int i = 0; i < n_normal; ++i) {
        auto Zx = compute_zx(e, builder.pubkeys[i]);
        auto ri = compute_ri(Zx, i);
        builder.pubkeys[i] = compute_blinded_key(builder.pubkeys[i], ri);
    }

    // Blind refund pubkeys (slots n_normal..n_normal+n_refund-1)
    for (int i = 0; i < n_refund; ++i) {
        auto Zx = compute_zx(e, builder.refund_pubkeys[i]);
        auto ri = compute_ri(Zx, n_normal + i);
        builder.refund_pubkeys[i] = compute_blinded_key(builder.refund_pubkeys[i], ri);
    }

    return builder.build();
}

pair<P2PKProofSecret, PubKey> build_blinded(P2PKBuilder builder) {
    unsigned char key_bytes[32];
    fill_random(key_bytes, 32);
    PrivKey e(key_bytes);
    internal::secure_zero(key_bytes, 32);

    PubKey E = e.get_pub_key();
    auto ps = build_blinded(move(builder), e);
    return {move(ps), move(E)};
}

// ============================================================
// NUT-28 P2BK: Blind witness generation
// ============================================================

// Try to sign for a set of allowed (blinded) pubkeys.
// slot_offset adjusts ri derivation index (0 for normal path,
// n_normal for refund path — fixes DotNut slot indexing bug).
static pair<bool, P2PKWitness> try_sign_blind_path(
    const vector<PubKey>& allowed_keys, int required_sigs,
    const vector<PrivKey>& available_keys, const PubKey& E,
    const unsigned char hash[32], int slot_offset)
{
    auto ctx = get_context();
    P2PKWitness result;
    set<int> used_slots;

    for (const auto& key : available_keys) {
        if (static_cast<int>(result.signatures.size()) >= required_sigs)
            break;

        auto Zx = compute_zx(key, E);

        for (int i = 0; i < static_cast<int>(allowed_keys.size()); ++i) {
            if (used_slots.count(i)) continue;

            int slot = slot_offset + i;
            auto ri = compute_ri(Zx, slot);

            // Standard derivation: p + ri
            bool found = false;
            {
                unsigned char sk[32];
                memcpy(sk, key.data(), 32);
                if (secp256k1_ec_seckey_tweak_add(ctx, sk, ri.data())) {
                    PrivKey tweaked(sk);
                    if (tweaked.get_pub_key() == allowed_keys[i]) {
                        used_slots.insert(i);
                        result.signatures.push_back(schnorr_sign(hash, tweaked));
                        found = true;
                    }
                }
                internal::secure_zero(sk, 32);
            }
            if (found) break;

            // Negated derivation: -p + ri
            {
                unsigned char sk[32];
                memcpy(sk, key.data(), 32);
                if (!secp256k1_ec_seckey_negate(ctx, sk))
                    continue;
                if (secp256k1_ec_seckey_tweak_add(ctx, sk, ri.data())) {
                    PrivKey tweaked(sk);
                    if (tweaked.get_pub_key() == allowed_keys[i]) {
                        used_slots.insert(i);
                        result.signatures.push_back(schnorr_sign(hash, tweaked));
                        found = true;
                    }
                }
                internal::secure_zero(sk, 32);
            }
            if (found) break;
        }
    }

    return {static_cast<int>(result.signatures.size()) >= required_sigs, result};
}

optional<P2PKWitness> generate_blind_witness(
    const P2PKProofSecret& ps,
    const vector<unsigned char>& msg,
    const vector<PrivKey>& keys,
    const PubKey& E)
{
    auto hash = internal::SHA256::hash(msg);

    int req_sigs = 0;
    auto allowed_keys = ps.get_allowed_pubkeys(req_sigs);
    optional<int> req_refund_sigs;
    auto allowed_refund_keys = ps.get_allowed_refund_pubkeys(req_refund_sigs);

    // If refund sigs == 0, proof is freely spendable
    if (req_refund_sigs.has_value() && req_refund_sigs.value() == 0)
        return nullopt;

    // Try normal path (slot offset = 0)
    auto [valid, witness] = try_sign_blind_path(
        allowed_keys, req_sigs, keys, E, hash.data(), 0);
    if (valid)
        return witness;

    // If locktime expired, try refund path (slot offset = n_normal)
    if (req_refund_sigs.has_value() && !allowed_refund_keys.empty()) {
        int refund_offset = static_cast<int>(allowed_keys.size());
        auto [refund_valid, refund_witness] = try_sign_blind_path(
            allowed_refund_keys, req_refund_sigs.value(), keys, E,
            hash.data(), refund_offset);
        if (refund_valid)
            return refund_witness;
    }

    throw runtime_error("P2BK: not enough valid keys to sign any blind path");
}

} // namespace nutcpp
