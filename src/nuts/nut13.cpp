#include "nutcpp/nuts/nut13.h"
#include "nutcpp/encoding/convert_utils.h"
#include "bip32.h"
#include "hmac_sha256.h"

#include <stdexcept>
#include <cstring>

using namespace std;

namespace nutcpp {

uint32_t get_keyset_id_int(const KeysetId& keyset_id) {
    // Take first 16 hex chars (8 bytes) of keyset ID, interpret as big-endian, mod (2^31 - 1)
    string id_hex = keyset_id.to_string();
    // v1 IDs (prefix 01) can be >16 chars; truncate to first 16 hex chars (8 bytes)
    if (id_hex.size() > 16)
        id_hex = id_hex.substr(0, 16);

    auto bytes = hex_to_bytes(id_hex);
    uint64_t val = 0;
    for (auto b : bytes)
        val = (val << 8) | b;

    return static_cast<uint32_t>(val % 0x7FFFFFFFUL); // mod (2^31 - 1)
}

string get_derivation_path(const KeysetId& keyset_id,
                           uint32_t counter,
                           bool secret_or_r) {
    uint32_t kid_int = get_keyset_id_int(keyset_id);
    // m/129372'/0'/{keyset_id_int}'/{counter}'/{0 or 1}
    return "m/129372'/0'/" + to_string(kid_int) + "'/" +
           to_string(counter) + "'/" + (secret_or_r ? "0" : "1");
}

// v0 (BIP-32) derivation
static string derive_secret_v0(const vector<uint8_t>& seed,
                                const KeysetId& keyset_id,
                                uint32_t counter) {
    string path = get_derivation_path(keyset_id, counter, true);
    auto key = internal::bip32_derive_path(path, seed.data(), seed.size());
    string hex = bytes_to_hex(key.private_key, 32);
    explicit_bzero(key.private_key, 32);
    explicit_bzero(key.chain_code, 32);
    return hex;
}

static vector<uint8_t> derive_blinding_factor_v0(const vector<uint8_t>& seed,
                                                  const KeysetId& keyset_id,
                                                  uint32_t counter) {
    string path = get_derivation_path(keyset_id, counter, false);
    auto key = internal::bip32_derive_path(path, seed.data(), seed.size());
    vector<uint8_t> r(key.private_key, key.private_key + 32);
    explicit_bzero(key.private_key, 32);
    explicit_bzero(key.chain_code, 32);
    return r;
}

// Build HMAC message: "Cashu_KDF_HMAC_SHA256" || keyset_id_bytes || counter(8 BE) || type_byte
static vector<unsigned char> build_hmac_message(const KeysetId& keyset_id,
                                                uint32_t counter,
                                                uint8_t type_byte) {
    static const string prefix = "Cashu_KDF_HMAC_SHA256";
    auto kid_bytes = hex_to_bytes(keyset_id.to_string());

    vector<unsigned char> message;
    message.reserve(prefix.size() + kid_bytes.size() + 8 + 1);

    message.insert(message.end(), prefix.begin(), prefix.end());
    message.insert(message.end(), kid_bytes.begin(), kid_bytes.end());

    // counter as uint64_t big-endian
    uint64_t c = counter;
    for (int i = 7; i >= 0; i--)
        message.push_back(static_cast<unsigned char>((c >> (i * 8)) & 0xff));

    message.push_back(type_byte);
    return message;
}

// v1 (HMAC-SHA256) derivation
static string derive_secret_v1(const vector<uint8_t>& seed,
                                const KeysetId& keyset_id,
                                uint32_t counter) {
    auto message = build_hmac_message(keyset_id, counter, 0x00);
    auto digest = internal::hmac_sha256(seed.data(), seed.size(),
                                         message.data(), message.size());
    return bytes_to_hex(digest.data(), digest.size());
}

static vector<uint8_t> derive_blinding_factor_v1(const vector<uint8_t>& seed,
                                                  const KeysetId& keyset_id,
                                                  uint32_t counter) {
    auto message = build_hmac_message(keyset_id, counter, 0x01);
    auto digest = internal::hmac_sha256(seed.data(), seed.size(),
                                         message.data(), message.size());
    // Return raw 32 bytes (caller does mod n reduction if needed)
    return vector<uint8_t>(digest.begin(), digest.end());
}

// Public API: dispatch by keyset version
string derive_secret(const vector<uint8_t>& seed,
                     const KeysetId& keyset_id,
                     uint32_t counter) {
    switch (keyset_id.get_version()) {
        case 0x00: return derive_secret_v0(seed, keyset_id, counter);
        case 0x01: return derive_secret_v1(seed, keyset_id, counter);
        default:
            throw invalid_argument("unsupported keyset version: " +
                                   to_string(keyset_id.get_version()));
    }
}

vector<uint8_t> derive_blinding_factor(const vector<uint8_t>& seed,
                                       const KeysetId& keyset_id,
                                       uint32_t counter) {
    switch (keyset_id.get_version()) {
        case 0x00: return derive_blinding_factor_v0(seed, keyset_id, counter);
        case 0x01: return derive_blinding_factor_v1(seed, keyset_id, counter);
        default:
            throw invalid_argument("unsupported keyset version: " +
                                   to_string(keyset_id.get_version()));
    }
}

} // namespace nutcpp
