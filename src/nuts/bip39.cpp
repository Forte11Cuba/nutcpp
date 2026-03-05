#include "bip39.h"

#include <sstream>
#include <stdexcept>
#include <openssl/evp.h>
#include <cstring>

using namespace std;

namespace nutcpp {
namespace internal {

// Validate word count: BIP-39 allows 12, 15, 18, 21, or 24 words
static bool valid_word_count(int count) {
    return count == 12 || count == 15 || count == 18 ||
           count == 21 || count == 24;
}

// Normalize mnemonic: trim and collapse whitespace to single spaces.
// For English wordlist, no Unicode NFKD normalization is needed (all ASCII).
static string normalize_mnemonic(const string& mnemonic) {
    istringstream iss(mnemonic);
    string word;
    string result;
    int count = 0;
    while (iss >> word) {
        if (!result.empty())
            result += ' ';
        result += word;
        count++;
    }
    if (result.empty())
        throw invalid_argument("mnemonic is empty");
    if (!valid_word_count(count))
        throw invalid_argument("word count should be 12, 15, 18, 21 or 24");
    return result;
}

vector<uint8_t> mnemonic_to_seed(const string& mnemonic,
                                  const string& passphrase) {
    string normalized = normalize_mnemonic(mnemonic);

    // Salt = "mnemonic" + passphrase (BIP-39 spec)
    string salt = "mnemonic" + passphrase;

    vector<uint8_t> seed(64);
    int ok = PKCS5_PBKDF2_HMAC(
        normalized.data(),
        static_cast<int>(normalized.size()),
        reinterpret_cast<const unsigned char*>(salt.data()),
        static_cast<int>(salt.size()),
        2048,           // iterations
        EVP_sha512(),   // SHA-512
        64,             // output length
        seed.data()
    );

    if (ok != 1)
        throw runtime_error("PBKDF2-HMAC-SHA512 failed");

    return seed;
}

} // namespace internal
} // namespace nutcpp
