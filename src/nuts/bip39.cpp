#include "bip39.h"
#include "bip39_wordlist.h"
#include "../crypto/sha256.h"

#include <sstream>
#include <stdexcept>
#include <limits>
#include <unordered_map>
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

// Build a static word -> index map from BIP-39 English wordlist for O(1) lookup
static const unordered_map<string, int>& wordlist_map() {
    static const unordered_map<string, int> m = [] {
        const auto& words = bip39_wordlist();
        unordered_map<string, int> result;
        result.reserve(words.size());
        for (size_t i = 0; i < words.size(); i++)
            result[words[i]] = static_cast<int>(i);
        return result;
    }();
    return m;
}

// Split mnemonic into words, trim whitespace
static vector<string> split_words(const string& mnemonic) {
    istringstream iss(mnemonic);
    vector<string> words;
    string word;
    while (iss >> word)
        words.push_back(word);
    return words;
}

// Normalize mnemonic: trim whitespace, validate word count and each word against BIP-39 English.
// BIP-39 spec requires NFKD normalization, but English words are pure ASCII so NFKD is a no-op.
// Non-ASCII passphrases would need NFKD — not supported (English-only, like DotNut).
static string normalize_mnemonic(const string& mnemonic) {
    auto words = split_words(mnemonic);

    if (words.empty())
        throw invalid_argument("mnemonic is empty");
    if (!valid_word_count(static_cast<int>(words.size())))
        throw invalid_argument("word count should be 12, 15, 18, 21 or 24");

    // Validate each word exists in BIP-39 English wordlist
    const auto& wmap = wordlist_map();
    string result;
    for (const auto& w : words) {
        if (wmap.find(w) == wmap.end())
            throw invalid_argument("mnemonic contains an invalid BIP-39 word");
        if (!result.empty())
            result += ' ';
        result += w;
    }

    return result;
}

// Securely wipe a string's internal buffer
static void secure_wipe(string& s) {
    if (!s.empty())
        OPENSSL_cleanse(&s[0], s.size());
    s.clear();
}

bool validate_mnemonic_checksum(const string& mnemonic) {
    auto words = split_words(mnemonic);

    int word_count = static_cast<int>(words.size());
    if (!valid_word_count(word_count))
        return false;

    // Convert words to 11-bit indices
    const auto& wmap = wordlist_map();
    vector<int> indices;
    indices.reserve(words.size());
    for (const auto& w : words) {
        auto it = wmap.find(w);
        if (it == wmap.end())
            return false;
        indices.push_back(it->second);
    }

    // BIP-39: CS = word_count / 3, ENT = total_bits - CS
    int total_bits = word_count * 11;
    int cs_bits = word_count / 3;
    int ent_bits = total_bits - cs_bits;

    // Convert indices to bit stream and extract entropy bytes
    int ent_bytes = ent_bits / 8;
    vector<unsigned char> entropy(ent_bytes, 0);
    for (int i = 0; i < ent_bits; i++) {
        int idx = indices[i / 11];
        int bit_pos = 10 - (i % 11);
        if ((idx >> bit_pos) & 1)
            entropy[i / 8] |= (1 << (7 - (i % 8)));
    }

    // SHA-256 of entropy
    auto hash = SHA256::hash(entropy);

    // Compare first cs_bits of hash with checksum bits from mnemonic
    for (int i = 0; i < cs_bits; i++) {
        int mnemonic_bit_pos = ent_bits + i;
        int idx = indices[mnemonic_bit_pos / 11];
        int bit_in_idx = 10 - (mnemonic_bit_pos % 11);
        bool checksum_bit = (idx >> bit_in_idx) & 1;

        bool hash_bit = (hash[i / 8] >> (7 - (i % 8))) & 1;

        if (hash_bit != checksum_bit)
            return false;
    }

    return true;
}

vector<uint8_t> mnemonic_to_seed(const string& mnemonic,
                                  const string& passphrase) {
    string normalized = normalize_mnemonic(mnemonic);

    // Validate BIP-39 checksum
    if (!validate_mnemonic_checksum(normalized))
        throw invalid_argument("mnemonic has invalid BIP-39 checksum");

    // Salt = "mnemonic" + passphrase (BIP-39 spec)
    string salt = "mnemonic" + passphrase;

    // Guard size_t -> int narrowing (PKCS5_PBKDF2_HMAC takes int lengths)
    if (normalized.size() > static_cast<size_t>(numeric_limits<int>::max()) ||
        salt.size() > static_cast<size_t>(numeric_limits<int>::max())) {
        secure_wipe(normalized);
        secure_wipe(salt);
        throw invalid_argument("mnemonic or passphrase too long");
    }

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
