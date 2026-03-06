#include "nutcpp/wallet/blinding_helper.h"
#include "nutcpp/crypto/cashu.h"
#include "nutcpp/encoding/convert_utils.h"
#include <stdexcept>
#include <cstring>

#ifdef __linux__
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#error "No secure random source available for this platform"
#endif

using namespace std;

namespace nutcpp::wallet {

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
#endif
}

static string random_hex(size_t n_bytes) {
    vector<unsigned char> buf(n_bytes);
    fill_random(buf.data(), n_bytes);
    return bytes_to_hex(buf.data(), buf.size());
}

// ============================================================
// split_amount
// ============================================================

vector<uint64_t> split_amount(uint64_t amount) {
    vector<uint64_t> result;
    uint64_t bit = 1;
    while (amount > 0) {
        if (amount & 1)
            result.push_back(bit);
        amount >>= 1;
        bit <<= 1;
    }
    return result;
}

// ============================================================
// create_blinded_outputs (random)
// ============================================================

BlindedOutputs create_blinded_outputs(const vector<uint64_t>& amounts,
                                      const KeysetId& keyset_id) {
    BlindedOutputs result;
    result.blinding_data.reserve(amounts.size());
    result.blinded_messages.reserve(amounts.size());

    for (auto amt : amounts) {
        // Random 32-byte secret as hex string (64 chars)
        StringSecret secret(random_hex(32));
        // Random 32-byte blinding factor
        unsigned char r_bytes[32];
        fill_random(r_bytes, 32);
        PrivKey r(r_bytes);
        explicit_bzero(r_bytes, 32);

        PubKey Y = secret.to_curve();
        PubKey B_ = crypto::compute_B_(Y, r);

        result.blinded_messages.emplace_back(amt, keyset_id, B_);
        result.blinding_data.emplace_back(secret, r);
    }

    return result;
}

// ============================================================
// create_blinded_outputs (deterministic, NUT-13)
// ============================================================

BlindedOutputs create_blinded_outputs(const vector<uint64_t>& amounts,
                                      const KeysetId& keyset_id,
                                      const vector<StringSecret>& secrets,
                                      const vector<PrivKey>& blinding_factors) {
    if (secrets.size() != amounts.size())
        throw invalid_argument("secrets.size() must equal amounts.size()");
    if (blinding_factors.size() != amounts.size())
        throw invalid_argument("blinding_factors.size() must equal amounts.size()");

    BlindedOutputs result;
    result.blinding_data.reserve(amounts.size());
    result.blinded_messages.reserve(amounts.size());

    for (size_t i = 0; i < amounts.size(); ++i) {
        PubKey Y = secrets[i].to_curve();
        PubKey B_ = crypto::compute_B_(Y, blinding_factors[i]);

        result.blinded_messages.emplace_back(amounts[i], keyset_id, B_);
        result.blinding_data.emplace_back(secrets[i], blinding_factors[i]);
    }

    return result;
}

// ============================================================
// unblind_signatures
// ============================================================

vector<Proof> unblind_signatures(const vector<BlindSignature>& signatures,
                                 const vector<BlindingData>& blinding_data,
                                 const Keyset& keyset) {
    if (signatures.size() != blinding_data.size())
        throw invalid_argument("signatures.size() must equal blinding_data.size()");

    vector<Proof> proofs;
    proofs.reserve(signatures.size());

    for (size_t i = 0; i < signatures.size(); ++i) {
        const auto& sig = signatures[i];
        const auto& bd = blinding_data[i];

        // Look up mint public key A for this denomination
        auto it = keyset.find(sig.amount);
        if (it == keyset.end())
            throw runtime_error("No public key in keyset for amount " + to_string(sig.amount));
        const PubKey& A = it->second;

        // Unblind: C = C_ - rA
        PubKey C = crypto::compute_C(sig.C_, bd.r, A);

        proofs.emplace_back(sig.amount, sig.id, bd.secret.value(), C,
                            nullopt, sig.dleq);
    }

    return proofs;
}

} // namespace nutcpp::wallet
