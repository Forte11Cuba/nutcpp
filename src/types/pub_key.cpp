#include "nutcpp/types/pub_key.h"
#include <algorithm>
#include <sstream>
#include <iomanip>

using namespace std;

namespace nutcpp {

// TODO: move to a shared context when more files need it
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
        ss << std::hex << hex.substr(i * 2, 2);
        if (!(ss >> byte) || byte > 0xFF) {
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

// --- PubKey ---

PubKey::PubKey(const string& hex) {
    if (hex.size() != 66) {
        throw invalid_argument("Expected compressed public key (66 hex chars)");
    }
    auto bytes = hex_to_bytes(hex);
    if (!secp256k1_ec_pubkey_parse(get_context(), &key_, bytes.data(), bytes.size())) {
        throw invalid_argument("Invalid public key");
    }
}

PubKey::PubKey(const secp256k1_pubkey& key) : key_(key) {}

string PubKey::to_hex() const {
    unsigned char buf[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(get_context(), buf, &len, &key_, SECP256K1_EC_COMPRESSED);
    return bytes_to_hex(buf, len);
}

bool PubKey::operator==(const PubKey& other) const {
    return secp256k1_ec_pubkey_cmp(get_context(), &key_, &other.key_) == 0;
}

// --- JSON ---

void to_json(nlohmann::json& j, const PubKey& pk) {
    j = pk.to_hex();
}

void from_json(const nlohmann::json& j, PubKey& pk) {
    pk = PubKey(j.get<string>());
}

} // namespace nutcpp
