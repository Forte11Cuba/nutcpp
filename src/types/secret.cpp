#include "nutcpp/types/secret.h"

using namespace std;

namespace nutcpp {

// --- StringSecret ---

StringSecret::StringSecret(const string& secret) : secret_(secret) {
    if (secret_.empty())
        throw invalid_argument("Secret cannot be empty");
}

vector<unsigned char> StringSecret::get_bytes() const {
    return vector<unsigned char>(secret_.begin(), secret_.end());
}

PubKey StringSecret::to_curve() const {
    // TODO: implement when crypto/cashu.h (HashToCurve) is available
    throw runtime_error("to_curve() not yet implemented — needs crypto/cashu.h");
}

// --- JSON ---

void to_json(nlohmann::json& j, const StringSecret& s) {
    j = s.value();
}

void from_json(const nlohmann::json& j, StringSecret& s) {
    s = StringSecret(j.get<string>());
}

} // namespace nutcpp
