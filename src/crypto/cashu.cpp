#include "nutcpp/crypto/cashu.h"
#include "nutcpp/encoding/convert_utils.h"
#include "sha256.h"

#include <secp256k1.h>
#include <cstring>
#include <stdexcept>

#ifdef __linux__
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#else
#include <random>
#endif

using namespace std;

namespace nutcpp {
namespace crypto {

// Fill buffer with cryptographically secure random bytes
static void fill_random(unsigned char* buf, size_t len) {
#ifdef __linux__
    ssize_t ret = getrandom(buf, len, 0);
    if (ret < 0 || static_cast<size_t>(ret) != len)
        throw runtime_error("getrandom() failed");
#elif defined(__APPLE__)
    if (SecRandomCopyBytes(kSecRandomDefault, len, buf) != errSecSuccess)
        throw runtime_error("SecRandomCopyBytes() failed");
#else
    random_device rd;
    for (size_t i = 0; i < len; ++i)
        buf[i] = static_cast<unsigned char>(rd());
#endif
}

// Shared secp256k1 context (sign + verify), randomized for side-channel protection
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

// ============================================================
// Internal helpers
// ============================================================

// Serialize pubkey to compressed bytes (33 bytes)
static vector<unsigned char> pubkey_to_bytes(const secp256k1_pubkey& pk) {
    auto ctx = get_context();
    vector<unsigned char> out(33);
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out.data(), &len, &pk, SECP256K1_EC_COMPRESSED);
    return out;
}

// Serialize pubkey to uncompressed bytes (65 bytes)
static vector<unsigned char> pubkey_to_uncompressed(const secp256k1_pubkey& pk) {
    auto ctx = get_context();
    vector<unsigned char> out(65);
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(ctx, out.data(), &len, &pk, SECP256K1_EC_UNCOMPRESSED);
    return out;
}

// Point addition: result = a + b
static secp256k1_pubkey point_add(const secp256k1_pubkey& a, const secp256k1_pubkey& b) {
    auto ctx = get_context();
    const secp256k1_pubkey* ptrs[2] = {&a, &b};
    secp256k1_pubkey result;
    if (!secp256k1_ec_pubkey_combine(ctx, &result, ptrs, 2)) {
        throw runtime_error("secp256k1_ec_pubkey_combine failed");
    }
    return result;
}

// Scalar * Point: result = scalar * point (works on a copy)
static secp256k1_pubkey scalar_mult(const secp256k1_pubkey& point, const unsigned char scalar[32]) {
    auto ctx = get_context();
    secp256k1_pubkey result = point; // copy
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &result, scalar)) {
        throw runtime_error("secp256k1_ec_pubkey_tweak_mul failed");
    }
    return result;
}

// Negate a point (works on a copy)
static secp256k1_pubkey point_negate(const secp256k1_pubkey& point) {
    auto ctx = get_context();
    secp256k1_pubkey result = point; // copy
    if (!secp256k1_ec_pubkey_negate(ctx, &result)) {
        throw runtime_error("secp256k1_ec_pubkey_negate failed");
    }
    return result;
}

// Derive pubkey from secret key: result = scalar * G
static secp256k1_pubkey scalar_to_point(const unsigned char scalar[32]) {
    auto ctx = get_context();
    secp256k1_pubkey result;
    if (!secp256k1_ec_pubkey_create(ctx, &result, scalar)) {
        throw runtime_error("secp256k1_ec_pubkey_create failed");
    }
    return result;
}

// ============================================================
// NUT-00: Hash to curve
// ============================================================

static const unsigned char DOMAIN_SEPARATOR[] = "Secp256k1_HashToCurve_Cashu_";
static const size_t DOMAIN_SEPARATOR_LEN = 28; // strlen("Secp256k1_HashToCurve_Cashu_")

PubKey hash_to_curve(const vector<unsigned char>& x) {
    auto ctx = get_context();

    // msg_hash = SHA256(DOMAIN_SEPARATOR || x)
    internal::SHA256 sha;
    sha.update(DOMAIN_SEPARATOR, DOMAIN_SEPARATOR_LEN);
    sha.update(x);
    auto msg_hash = sha.finalize();

    // Try counter values until we find a valid point
    for (uint32_t counter = 0; ; counter++) {
        // candidate = 0x02 || SHA256(msg_hash || counter_le)
        unsigned char counter_le[4];
        counter_le[0] = static_cast<unsigned char>(counter & 0xff);
        counter_le[1] = static_cast<unsigned char>((counter >> 8) & 0xff);
        counter_le[2] = static_cast<unsigned char>((counter >> 16) & 0xff);
        counter_le[3] = static_cast<unsigned char>((counter >> 24) & 0xff);

        internal::SHA256 sha2;
        sha2.update(msg_hash);
        sha2.update(counter_le, 4);
        auto hash = sha2.finalize();

        // Prepend 0x02 to make a compressed pubkey candidate
        unsigned char candidate[33];
        candidate[0] = 0x02;
        memcpy(candidate + 1, hash.data(), 32);

        // Try to parse as a valid secp256k1 point
        secp256k1_pubkey pk;
        if (secp256k1_ec_pubkey_parse(ctx, &pk, candidate, 33)) {
            return PubKey{pk};
        }
    }
}

PubKey hex_to_curve(const string& hex) {
    auto bytes = hex_to_bytes(hex);
    return hash_to_curve(bytes);
}

PubKey message_to_curve(const string& message) {
    vector<unsigned char> bytes(message.begin(), message.end());
    return hash_to_curve(bytes);
}

// ============================================================
// NUT-00: BDHKE
// ============================================================

PubKey compute_B_(const PubKey& Y, const PrivKey& r) {
    // B_ = Y + rG
    auto rG = scalar_to_point(r.data());
    auto result = point_add(Y.get(), rG);
    return PubKey{result};
}

PubKey compute_C_(const PubKey& B_, const PrivKey& k) {
    // C_ = kB_
    auto result = scalar_mult(B_.get(), k.data());
    return PubKey{result};
}

PubKey compute_C(const PubKey& C_, const PrivKey& r, const PubKey& A) {
    // C = C_ - rA = C_ + (-(rA))
    auto rA = scalar_mult(A.get(), r.data());
    auto neg_rA = point_negate(rA);
    auto result = point_add(C_.get(), neg_rA);
    return PubKey{result};
}

// ============================================================
// NUT-12: DLEQ
// ============================================================

PrivKey compute_e(const PubKey& R1, const PubKey& R2, const PubKey& K, const PubKey& C_) {
    // Concatenate uncompressed hex representations of all pubkeys as UTF-8,
    // then SHA256 hash the result.
    auto r1_bytes = pubkey_to_uncompressed(R1.get());
    auto r2_bytes = pubkey_to_uncompressed(R2.get());
    auto k_bytes = pubkey_to_uncompressed(K.get());
    auto c_bytes = pubkey_to_uncompressed(C_.get());

    string concat;
    concat += bytes_to_hex(r1_bytes.data(), r1_bytes.size());
    concat += bytes_to_hex(r2_bytes.data(), r2_bytes.size());
    concat += bytes_to_hex(k_bytes.data(), k_bytes.size());
    concat += bytes_to_hex(c_bytes.data(), c_bytes.size());

    // SHA256 of the UTF-8 encoded concatenated hex string
    auto hash = internal::SHA256::hash(concat);
    return PrivKey{hash.data()};
}

pair<PrivKey, PrivKey> compute_proof(const PubKey& B_, const PrivKey& a, const PrivKey& p) {
    // r1 = pG
    auto r1 = scalar_to_point(p.data());
    // r2 = pB_
    auto r2 = scalar_mult(B_.get(), p.data());
    // C_ = aB_
    auto C_ = scalar_mult(B_.get(), a.data());
    // A = aG
    auto A = scalar_to_point(a.data());

    // e = hash(r1, r2, A, C_)
    PrivKey e = compute_e(PubKey{r1}, PubKey{r2}, PubKey{A}, PubKey{C_});

    // s = p + e*a
    auto ctx = get_context();
    unsigned char ea[32];
    memcpy(ea, a.data(), 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, ea, e.data())) {
        throw runtime_error("secp256k1_ec_seckey_tweak_mul failed in compute_proof");
    }

    unsigned char s_bytes[32];
    memcpy(s_bytes, p.data(), 32);
    if (!secp256k1_ec_seckey_tweak_add(ctx, s_bytes, ea)) {
        throw runtime_error("secp256k1_ec_seckey_tweak_add failed in compute_proof");
    }

    return {e, PrivKey{s_bytes}};
}

bool verify_proof(const PubKey& B_, const PubKey& C_, const PrivKey& e, const PrivKey& s, const PubKey& A) {
    try {
        // R1 = sG - eA = sG + (-(eA))
        auto sG = scalar_to_point(s.data());
        auto eA = scalar_mult(A.get(), e.data());
        auto neg_eA = point_negate(eA);
        auto R1 = point_add(sG, neg_eA);

        // R2 = sB_ - eC_ = sB_ + (-(eC_))
        auto sB_ = scalar_mult(B_.get(), s.data());
        auto eC_ = scalar_mult(C_.get(), e.data());
        auto neg_eC_ = point_negate(eC_);
        auto R2 = point_add(sB_, neg_eC_);

        // e' = hash(R1, R2, A, C_)
        PrivKey e_computed = compute_e(PubKey{R1}, PubKey{R2}, A, C_);
        return memcmp(e.data(), e_computed.data(), 32) == 0;
    } catch (const std::exception&) {
        return false;
    }
}

bool verify_proof(const PubKey& Y, const PrivKey& r, const PubKey& C, const PrivKey& e, const PrivKey& s, const PubKey& A) {
    try {
        // Reconstruct C_ = C + rA
        auto rA = scalar_mult(A.get(), r.data());
        auto C_ = point_add(C.get(), rA);

        // Reconstruct B_ = Y + rG
        auto rG = scalar_to_point(r.data());
        auto B_ = point_add(Y.get(), rG);

        return verify_proof(PubKey{B_}, PubKey{C_}, e, s, A);
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace crypto
} // namespace nutcpp
