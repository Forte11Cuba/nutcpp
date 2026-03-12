#pragma once

// Internal HMAC-SHA256 implementation for NUT-13 v1 deterministic secrets.
// Built on top of internal::SHA256. Header-only.
// Reference: RFC 2104

#include "../crypto/sha256.h"

#include <vector>
#include <cstdint>
#include <cstring>
#include "../crypto/secure_zero.h"

namespace nutcpp {
namespace internal {

inline std::vector<unsigned char> hmac_sha256(const unsigned char* key, size_t key_len,
                                              const unsigned char* data, size_t data_len) {
    static constexpr size_t BLOCK_SIZE = 64;

    // Step 1: If key > block size, hash it
    unsigned char k_prime[BLOCK_SIZE];
    std::memset(k_prime, 0, BLOCK_SIZE);
    if (key_len > BLOCK_SIZE) {
        auto hashed = SHA256::hash(key, key_len);
        std::memcpy(k_prime, hashed.data(), 32);
    } else {
        std::memcpy(k_prime, key, key_len);
    }

    // Step 2: Inner hash = SHA256((K' XOR ipad) || data)
    unsigned char ipad[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++)
        ipad[i] = k_prime[i] ^ 0x36;

    SHA256 inner;
    inner.update(ipad, BLOCK_SIZE);
    inner.update(data, data_len);
    auto inner_hash = inner.finalize();

    // Step 3: Outer hash = SHA256((K' XOR opad) || inner_hash)
    unsigned char opad[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++)
        opad[i] = k_prime[i] ^ 0x5c;

    SHA256 outer;
    outer.update(opad, BLOCK_SIZE);
    outer.update(inner_hash.data(), inner_hash.size());
    auto result = outer.finalize();

    // Wipe key-derived material from stack
    secure_zero(k_prime, BLOCK_SIZE);
    secure_zero(ipad, BLOCK_SIZE);
    secure_zero(opad, BLOCK_SIZE);

    return result;
}

} // namespace internal
} // namespace nutcpp
