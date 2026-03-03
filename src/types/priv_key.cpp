#include "nutcpp/types/priv_key.h"
#include <cstring>
#include <sstream>
#include <iomanip>

using namespace std;

namespace nutcpp {

static const secp256k1_context* get_context() {
    static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return ctx;
}

// Hex helpers (will move to convert_utils.h later)

static vector<unsigned char> hex_to_bytes(const string& hex) {
    if (hex.size() % 2 != 0) {
        throw invalid_argument("Hex string must have even length");
    }
    vector<unsigned char> bytes(hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); i++) {
        unsigned int byte = 0;
        stringstream ss;
        ss << hex.substr(i * 2, 2);
        ss >> std::hex >> byte;
        if (ss.fail() || !ss.eof() || byte > 0xFF) {
            throw invalid_argument("Invalid hex string");
        }
        bytes[i] = static_cast<unsigned char>(byte);
    }
    return bytes;
}

static string bytes_to_hex(const unsigned char* data, size_t len) {
    ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << setfill('0') << setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
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

// --- JSON ---

void to_json(nlohmann::json& j, const PrivKey& sk) {
    j = sk.to_hex();
}

void from_json(const nlohmann::json& j, PrivKey& sk) {
    sk = PrivKey(j.get<string>());
}

} // namespace nutcpp
