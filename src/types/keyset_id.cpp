#include "nutcpp/types/keyset_id.h"
#include <algorithm>
#include <sstream>
#include <iomanip>

using namespace std;

namespace nutcpp {

// --- Helpers ---

static string to_lower(const string& s) {
    string result = s;
    transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

static vector<unsigned char> hex_to_bytes(const string& hex) {
    if (hex.size() % 2 != 0)
        throw invalid_argument("Hex string must have even length");
    vector<unsigned char> bytes(hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); i++) {
        unsigned int byte = 0;
        stringstream ss;
        ss << hex.substr(i * 2, 2);
        ss >> std::hex >> byte;
        if (ss.fail() || !ss.eof() || byte > 0xFF)
            throw invalid_argument("Invalid hex character in keyset ID");
        bytes[i] = static_cast<unsigned char>(byte);
    }
    return bytes;
}

// --- KeysetId ---

KeysetId::KeysetId(const string& id) : id_(id) {
    if (id_.size() != 16 && id_.size() != 66 && id_.size() != 12)
        throw invalid_argument(
            "KeysetId must be 16 (v1/v2 short), 66 (v2 full), or 12 (legacy) characters long");

    // Validate hex characters
    hex_to_bytes(id_);
}

uint8_t KeysetId::get_version() const {
    unsigned int ver = 0;
    stringstream ss;
    ss << id_.substr(0, 2);
    ss >> std::hex >> ver;
    return static_cast<uint8_t>(ver);
}

vector<unsigned char> KeysetId::get_bytes() const {
    return hex_to_bytes(id_);
}

bool KeysetId::operator==(const KeysetId& other) const {
    return to_lower(id_) == to_lower(other.id_);
}

bool KeysetId::operator<(const KeysetId& other) const {
    return to_lower(id_) < to_lower(other.id_);
}

// --- JSON ---

void to_json(nlohmann::json& j, const KeysetId& kid) {
    j = kid.to_string();
}

void from_json(const nlohmann::json& j, KeysetId& kid) {
    kid = KeysetId(j.get<string>());
}

} // namespace nutcpp
