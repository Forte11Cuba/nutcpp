#include "nutcpp/types/keyset_id.h"
#include "nutcpp/encoding/convert_utils.h"
#include <algorithm>

using namespace std;

namespace nutcpp {

static string to_lower(const string& s) {
    string result = s;
    transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
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
    unsigned char hi = hex_nibble(id_[0]);
    unsigned char lo = hex_nibble(id_[1]);
    return static_cast<uint8_t>((hi << 4) | lo);
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

} // namespace nutcpp
