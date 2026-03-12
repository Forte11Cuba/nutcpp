#include "bip32.h"

#include <stdexcept>
#include <sstream>
#include <cstring>
#include <utility>
#include "../crypto/secure_zero.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <secp256k1.h>

#ifdef __linux__
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(_WIN32)
#include <bcrypt.h>
#pragma comment(lib, "bcrypt")
#else
#error "No secure random source available for this platform"
#endif

using namespace std;

namespace nutcpp {
namespace internal {

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

static secp256k1_context* get_context() {
    static secp256k1_context* ctx = [] {
        auto* c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        unsigned char seed[32];
        fill_random(seed, 32);
        if (!secp256k1_context_randomize(c, seed)) {
            secp256k1_context_destroy(c);
            throw runtime_error("secp256k1_context_randomize failed");
        }
        internal::secure_zero(seed, 32);
        return c;
    }();
    return ctx;
}

// HMAC-SHA512: output must be 64 bytes
static void hmac_sha512(const unsigned char* key, int key_len,
                         const unsigned char* data, size_t data_len,
                         unsigned char out[64]) {
    unsigned int len = 64;
    if (!HMAC(EVP_sha512(), key, key_len, data, data_len, out, &len))
        throw runtime_error("BIP32: HMAC-SHA512 failed");
}

BIP32Key bip32_master_key(const uint8_t* seed, size_t seed_len) {
    static const unsigned char curve_key[] = "Bitcoin seed"; // 12 bytes

    unsigned char hash[64];
    hmac_sha512(curve_key, 12, seed, seed_len, hash);

    BIP32Key key;
    memcpy(key.private_key, hash, 32);
    memcpy(key.chain_code, hash + 32, 32);

    internal::secure_zero(hash, 64);

    // Validate key is in valid range (0 < key < n)
    if (!secp256k1_ec_seckey_verify(get_context(), key.private_key))
        throw runtime_error("BIP32: invalid master key derived from seed");

    return key;
}

static BIP32Key derive_child(const BIP32Key& parent, uint32_t index, bool hardened) {
    unsigned char data[37]; // max: 0x00 + 32 key + 4 index, or 33 pubkey + 4 index
    size_t data_len;

    uint32_t child_index = hardened ? (index | 0x80000000u) : index;

    if (hardened) {
        // Hardened: 0x00 || parent_private_key || index
        data[0] = 0x00;
        memcpy(data + 1, parent.private_key, 32);
        data[33] = static_cast<unsigned char>((child_index >> 24) & 0xff);
        data[34] = static_cast<unsigned char>((child_index >> 16) & 0xff);
        data[35] = static_cast<unsigned char>((child_index >> 8) & 0xff);
        data[36] = static_cast<unsigned char>(child_index & 0xff);
        data_len = 37;
    } else {
        // Non-hardened: compressed_pubkey || index
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(get_context(), &pubkey, parent.private_key))
            throw runtime_error("BIP32: failed to create public key");

        size_t pub_len = 33;
        secp256k1_ec_pubkey_serialize(get_context(), data, &pub_len,
                                      &pubkey, SECP256K1_EC_COMPRESSED);

        data[33] = static_cast<unsigned char>((child_index >> 24) & 0xff);
        data[34] = static_cast<unsigned char>((child_index >> 16) & 0xff);
        data[35] = static_cast<unsigned char>((child_index >> 8) & 0xff);
        data[36] = static_cast<unsigned char>(child_index & 0xff);
        data_len = 37;
    }

    unsigned char hash[64];
    hmac_sha512(parent.chain_code, 32, data, data_len, hash);

    BIP32Key child;
    // child_key = (IL + parent_key) mod n
    memcpy(child.private_key, parent.private_key, 32);
    if (!secp256k1_ec_seckey_tweak_add(get_context(), child.private_key, hash))
        throw runtime_error("BIP32: derived key is invalid");

    memcpy(child.chain_code, hash + 32, 32);

    internal::secure_zero(hash, 64);
    internal::secure_zero(data, sizeof(data));
    return child;
}

// Parse path like "m/129372'/0'/864559728'/0'/0"
static vector<pair<uint32_t, bool>> parse_path(const string& path) {
    vector<pair<uint32_t, bool>> result;
    istringstream iss(path);
    string segment;

    // Skip "m" prefix
    getline(iss, segment, '/');
    if (segment != "m")
        throw invalid_argument("BIP32 path must start with 'm'");

    while (getline(iss, segment, '/')) {
        bool hardened = false;
        if (!segment.empty() && segment.back() == '\'') {
            hardened = true;
            segment.pop_back();
        }
        if (segment.empty())
            throw invalid_argument("BIP32 path has empty segment");
        unsigned long val = stoul(segment);
        if (val >= 0x80000000UL)
            throw invalid_argument("BIP32 index must be < 2^31");
        uint32_t index = static_cast<uint32_t>(val);
        result.push_back({index, hardened});
    }

    return result;
}

BIP32Key bip32_derive_path(const string& path,
                           const uint8_t* seed, size_t seed_len) {
    auto segments = parse_path(path);
    BIP32Key key = bip32_master_key(seed, seed_len);

    for (const auto& [index, hardened] : segments) {
        BIP32Key child = derive_child(key, index, hardened);
        internal::secure_zero(key.private_key, 32);
        internal::secure_zero(key.chain_code, 32);
        key = child;
        internal::secure_zero(child.private_key, 32);
        internal::secure_zero(child.chain_code, 32);
    }

    return key;
}

} // namespace internal
} // namespace nutcpp
