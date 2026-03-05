#include "bip32.h"

#include <stdexcept>
#include <sstream>
#include <cstring>
#include <utility>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <secp256k1.h>

using namespace std;

namespace nutcpp {
namespace internal {

static secp256k1_context* get_context() {
    static secp256k1_context* ctx = [] {
        auto* c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        unsigned char rng_seed[32];
        FILE* f = fopen("/dev/urandom", "rb");
        if (f) {
            size_t read = fread(rng_seed, 1, 32, f);
            fclose(f);
            if (read == 32) {
                if (!secp256k1_context_randomize(c, rng_seed)) {
                    secp256k1_context_destroy(c);
                    throw runtime_error("secp256k1_context_randomize failed");
                }
            }
            explicit_bzero(rng_seed, 32);
        }
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

    explicit_bzero(hash, 64);

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

    explicit_bzero(hash, 64);
    explicit_bzero(data, sizeof(data));
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
        uint32_t index = static_cast<uint32_t>(stoul(segment));
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
        explicit_bzero(key.private_key, 32);
        explicit_bzero(key.chain_code, 32);
        key = child;
    }

    return key;
}

} // namespace internal
} // namespace nutcpp
