#include "nutcpp/types/priv_key.h"
#include "nutcpp/encoding/convert_utils.h"
#include <cstring>

using namespace std;

namespace nutcpp {

static const secp256k1_context* get_context() {
    static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return ctx;
}

// --- PrivKey ---

PrivKey::~PrivKey() {
    explicit_bzero(key_, 32);
}

PrivKey::PrivKey(const string& hex) {
    if (hex.size() != 64) {
        throw invalid_argument("Expected private key (64 hex chars)");
    }
    auto bytes = hex_to_bytes(hex);
    if (!secp256k1_ec_seckey_verify(get_context(), bytes.data())) {
        throw invalid_argument("Invalid private key");
    }
    memcpy(key_, bytes.data(), 32);
}

PrivKey::PrivKey(const unsigned char key[32]) {
    if (!key) {
        throw invalid_argument("Key pointer must not be null");
    }
    if (!secp256k1_ec_seckey_verify(get_context(), key)) {
        throw invalid_argument("Invalid private key");
    }
    memcpy(key_, key, 32);
}

string PrivKey::to_hex() const {
    return bytes_to_hex(key_, 32);
}

PubKey PrivKey::get_pub_key() const {
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(get_context(), &pubkey, key_)) {
        throw runtime_error("Failed to derive public key");
    }
    return PubKey(pubkey);
}

} // namespace nutcpp
