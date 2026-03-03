#include "nutcpp/types/pub_key.h"
#include "nutcpp/encoding/convert_utils.h"

using namespace std;

namespace nutcpp {

static const secp256k1_context* get_context() {
    static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return ctx;
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
