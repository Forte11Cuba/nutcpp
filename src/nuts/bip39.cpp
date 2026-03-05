#include "bip39.h"
#include "bip39_wordlist.h"

#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <cstring>

using namespace std;

namespace nutcpp {
namespace internal {

// Validate word count: BIP-39 allows 12, 15, 18, 21, or 24 words
static bool valid_word_count(int count) {
    return count == 12 || count == 15 || count == 18 ||
           count == 21 || count == 24;
}

// Build a static lookup set from the BIP-39 English wordlist for O(1) validation
static const unordered_set<string>& wordlist_set() {
    static const unordered_set<string> s = [] {
        const auto& words = bip39_wordlist();
        return unordered_set<string>(words.begin(), words.end());
    }();
    return s;
}

// Normalize mnemonic: trim, collapse whitespace, validate each word against BIP-39 English.
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

    // Validate each word exists in BIP-39 English wordlist
    const auto& valid_words = wordlist_set();
    istringstream iss2(result);
    while (iss2 >> word) {
        if (valid_words.find(word) == valid_words.end())
            throw invalid_argument("invalid mnemonic word: " + word);
    }

    return result;
}

// Securely wipe a string's internal buffer
static void secure_wipe(string& s) {
    if (!s.empty())
        OPENSSL_cleanse(&s[0], s.size());
    s.clear();
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

    // Wipe sensitive buffers before returning or throwing
    secure_wipe(normalized);
    secure_wipe(salt);

    if (ok != 1) {
        OPENSSL_cleanse(seed.data(), seed.size());
        throw runtime_error("PBKDF2-HMAC-SHA512 failed");
    }

    return seed;
}

} // namespace internal
} // namespace nutcpp
