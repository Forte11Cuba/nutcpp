#include "nutcpp/types/secret.h"
#include "nutcpp/crypto/cashu.h"

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
    return crypto::message_to_curve(secret_);
}

} // namespace nutcpp
