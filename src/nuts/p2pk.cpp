#include "nutcpp/nuts/p2pk.h"
#include "nutcpp/encoding/convert_utils.h"
#include "../crypto/sha256.h"

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <cstring>
#include <stdexcept>
#include <chrono>

#ifdef __linux__
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#else
#include <random>
#endif

using namespace std;

namespace nutcpp {

// ============================================================
// Internal helpers
// ============================================================

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

static string random_hex(size_t n_bytes) {
    vector<unsigned char> buf(n_bytes);
    fill_random(buf.data(), n_bytes);
    return bytes_to_hex(buf.data(), buf.size());
}

// Shared secp256k1 context — must match the one in cashu.cpp
// Using a separate static context here for the schnorrsig module
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

static vector<unsigned char> sha256_hash(const unsigned char* data, size_t len) {
    return internal::SHA256::hash(data, len);
}

static vector<unsigned char> sha256_hash(const vector<unsigned char>& data) {
    return internal::SHA256::hash(data.data(), data.size());
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

// BIP-340 Schnorr verify: msg must be 32 bytes, sig_hex is 128-char hex.
static bool schnorr_verify(const unsigned char msg[32], const string& sig_hex, const PubKey& pubkey) {
    if (sig_hex.size() != 128) return false;

    auto ctx = get_context();
    auto sig_bytes = hex_to_bytes(sig_hex);
    if (sig_bytes.size() != 64) return false;

    secp256k1_xonly_pubkey xonly;
    int parity;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, &parity, &pubkey.get()))
        return false;

    return secp256k1_schnorrsig_verify(ctx, sig_bytes.data(), msg, 32, &xonly) == 1;
}

static int64_t now_unix() {
    return chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count();
}

// ============================================================
// P2PKBuilder
// ============================================================

Nut10ProofSecret P2PKBuilder::build() const {
    validate();

    P2PKProofSecret ps;
    ps.data = pubkeys.front().to_hex();
    ps.nonce = nonce.empty() ? random_hex(32) : nonce;

    vector<vector<string>> tag_list;

    // Additional pubkeys (first is in data)
    if (pubkeys.size() > 1) {
        vector<string> tag = {"pubkeys"};
        for (size_t i = 1; i < pubkeys.size(); ++i)
            tag.push_back(pubkeys[i].to_hex());
        tag_list.push_back(move(tag));
    }

    if (!sig_flag.empty())
        tag_list.push_back({"sigflag", sig_flag});

    if (lock.has_value()) {
        tag_list.push_back({"locktime", to_string(lock.value())});
        if (!refund_pubkeys.empty()) {
            vector<string> tag = {"refund"};
            for (const auto& pk : refund_pubkeys)
                tag.push_back(pk.to_hex());
            tag_list.push_back(move(tag));

            int rst = refund_signature_threshold.value_or(1);
            if (rst > 1)
                tag_list.push_back({"n_sigs_refund", to_string(rst)});
        }
    }

    if (signature_threshold > 1 && static_cast<int>(pubkeys.size()) >= signature_threshold)
        tag_list.push_back({"n_sigs", to_string(signature_threshold)});

    ps.tags = move(tag_list);
    return ps;
}

P2PKBuilder P2PKBuilder::load(const Nut10ProofSecret& ps) {
    P2PKBuilder b;

    // Primary pubkey from data
    PubKey primary(ps.data);
    b.pubkeys.push_back(primary);

    // Additional pubkeys from "pubkeys" tag
    auto* pubkeys_tag = ps.find_tag("pubkeys");
    if (pubkeys_tag && pubkeys_tag->size() > 1) {
        for (size_t i = 1; i < pubkeys_tag->size(); ++i)
            b.pubkeys.push_back(PubKey((*pubkeys_tag)[i]));
    }

    // Locktime
    auto* locktime_tag = ps.find_tag("locktime");
    if (locktime_tag && locktime_tag->size() >= 2) {
        try { b.lock = stoll((*locktime_tag)[1]); }
        catch (...) { /* ignore parse errors */ }
    }

    // Refund pubkeys
    auto* refund_tag = ps.find_tag("refund");
    if (refund_tag && refund_tag->size() > 1) {
        for (size_t i = 1; i < refund_tag->size(); ++i)
            b.refund_pubkeys.push_back(PubKey((*refund_tag)[i]));
    }

    // Refund signature threshold
    auto* n_sigs_refund_tag = ps.find_tag("n_sigs_refund");
    if (n_sigs_refund_tag && n_sigs_refund_tag->size() >= 2) {
        try { b.refund_signature_threshold = stoi((*n_sigs_refund_tag)[1]); }
        catch (...) {}
    }

    // Sig flag
    auto* sigflag_tag = ps.find_tag("sigflag");
    if (sigflag_tag && sigflag_tag->size() >= 2)
        b.sig_flag = (*sigflag_tag)[1];

    // Signature threshold
    auto* n_sigs_tag = ps.find_tag("n_sigs");
    if (n_sigs_tag && n_sigs_tag->size() >= 2) {
        try { b.signature_threshold = stoi((*n_sigs_tag)[1]); }
        catch (...) {}
    }

    b.nonce = ps.nonce;
    return b;
}

void P2PKBuilder::validate() const {
    if (pubkeys.empty())
        throw invalid_argument("P2PKBuilder: pubkeys must not be empty");
    if (static_cast<int>(pubkeys.size()) < signature_threshold)
        throw invalid_argument("P2PKBuilder: signature threshold bigger than provided pubkeys count");
    if (refund_signature_threshold.has_value()) {
        if (refund_pubkeys.empty() ||
            static_cast<int>(refund_pubkeys.size()) < refund_signature_threshold.value())
            throw invalid_argument("P2PKBuilder: refund signature threshold bigger than provided refund pubkeys count");
    }
}

// ============================================================
// P2PKProofSecret
// ============================================================

vector<PubKey> P2PKProofSecret::get_allowed_pubkeys(int& required_sigs) const {
    auto builder = P2PKBuilder::load(*this);
    required_sigs = builder.signature_threshold;
    return builder.pubkeys;
}

vector<PubKey> P2PKProofSecret::get_allowed_refund_pubkeys(optional<int>& required_sigs) const {
    auto builder = P2PKBuilder::load(*this);

    if (!builder.lock.has_value() || builder.lock.value() >= now_unix()) {
        // No locktime or locktime not expired: refund path not available
        required_sigs = nullopt;
        return {};
    }

    // Locktime expired
    if (builder.refund_pubkeys.empty()) {
        // No refund keys: proof is freely spendable without any signature
        required_sigs = 0;
        return {};
    }

    required_sigs = builder.refund_signature_threshold.value_or(1);
    return builder.refund_pubkeys;
}

optional<P2PKWitness> P2PKProofSecret::generate_witness(
    const vector<unsigned char>& msg, const vector<PrivKey>& keys) const
{
    auto hash = sha256_hash(msg);

    int req_sigs = 0;
    auto allowed_keys = get_allowed_pubkeys(req_sigs);
    optional<int> req_refund_sigs;
    auto allowed_refund_keys = get_allowed_refund_pubkeys(req_refund_sigs);

    // If refund sigs == 0, proof is freely spendable
    if (req_refund_sigs.has_value() && req_refund_sigs.value() == 0)
        return nullopt;

    // Try normal path
    auto [valid, witness] = try_sign_path(allowed_keys, req_sigs, keys, hash.data());
    if (valid)
        return witness;

    // If locktime expired, try refund path
    if (req_refund_sigs.has_value() && !allowed_refund_keys.empty()) {
        auto [refund_valid, refund_witness] = try_sign_path(
            allowed_refund_keys, req_refund_sigs.value(), keys, hash.data());
        if (refund_valid)
            return refund_witness;
    }

    throw runtime_error("P2PKProofSecret: not enough valid keys to sign");
}

pair<bool, P2PKWitness> P2PKProofSecret::try_sign_path(
    const vector<PubKey>& allowed_keys, int required_sigs,
    const vector<PrivKey>& available_keys, const unsigned char msg[32]) const
{
    P2PKWitness result;

    for (const auto& privkey : available_keys) {
        if (static_cast<int>(result.signatures.size()) >= required_sigs)
            break;

        auto pubkey = privkey.get_pub_key();
        for (const auto& allowed : allowed_keys) {
            if (pubkey == allowed) {
                auto sig = schnorr_sign(msg, privkey);
                result.signatures.push_back(move(sig));
                break;
            }
        }
    }

    return {static_cast<int>(result.signatures.size()) >= required_sigs, result};
}

bool P2PKProofSecret::verify_witness(const ISecret& secret, const P2PKWitness& witness) const {
    return verify_witness(secret.get_bytes(), witness);
}

bool P2PKProofSecret::verify_witness(const vector<unsigned char>& message, const P2PKWitness& witness) const {
    auto hash = sha256_hash(message);
    return verify_witness_hash(hash.data(), witness);
}

bool P2PKProofSecret::verify_witness_hash(const unsigned char hash[32], const P2PKWitness& witness) const {
    try {
        int req_sigs = 0;
        auto allowed_keys = get_allowed_pubkeys(req_sigs);
        optional<int> req_refund_sigs;
        auto allowed_refund_keys = get_allowed_refund_pubkeys(req_refund_sigs);

        // If refund sigs == 0, proof is freely spendable
        if (req_refund_sigs.has_value() && req_refund_sigs.value() == 0)
            return true;

        // Try normal path
        if (verify_path(allowed_keys, req_sigs, witness.signatures, hash))
            return true;

        // If locktime expired, try refund path
        if (req_refund_sigs.has_value() && !allowed_refund_keys.empty()) {
            if (verify_path(allowed_refund_keys, req_refund_sigs.value(), witness.signatures, hash))
                return true;
        }

        return false;
    } catch (const exception&) {
        return false;
    }
}

bool P2PKProofSecret::verify_path(
    const vector<PubKey>& allowed_keys, int required_sigs,
    const vector<string>& sig_hexes, const unsigned char hash[32]) const
{
    if (static_cast<int>(sig_hexes.size()) < required_sigs)
        return false;

    // Track which key indices have been used (no double-counting)
    vector<bool> used(allowed_keys.size(), false);
    int verified = 0;

    for (const auto& sig_hex : sig_hexes) {
        for (size_t i = 0; i < allowed_keys.size(); ++i) {
            if (!used[i] && schnorr_verify(hash, sig_hex, allowed_keys[i])) {
                used[i] = true;
                ++verified;
                break;
            }
        }
    }

    return verified >= required_sigs;
}

} // namespace nutcpp
