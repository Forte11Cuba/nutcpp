#pragma once

// Internal SHA-256 implementation for keyset ID derivation.
// Will be reused by crypto/cashu.cpp (HashToCurve) in a later phase.

#include <vector>
#include <cstdint>
#include <cstring>
#include <string>

namespace nutcpp {
namespace internal {

class SHA256 {
public:
    SHA256() { reset(); }

    void reset() {
        state_[0] = 0x6a09e667; state_[1] = 0xbb67ae85;
        state_[2] = 0x3c6ef372; state_[3] = 0xa54ff53a;
        state_[4] = 0x510e527f; state_[5] = 0x9b05688c;
        state_[6] = 0x1f83d9ab; state_[7] = 0x5be0cd19;
        count_ = 0;
        buf_len_ = 0;
    }

    void update(const unsigned char* data, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buf_[buf_len_++] = data[i];
            count_++;
            if (buf_len_ == 64) {
                transform(buf_);
                buf_len_ = 0;
            }
        }
    }

    void update(const std::string& s) {
        update(reinterpret_cast<const unsigned char*>(s.data()), s.size());
    }

    void update(const std::vector<unsigned char>& v) {
        update(v.data(), v.size());
    }

    std::vector<unsigned char> finalize() {
        uint64_t bit_count = count_ * 8;

        unsigned char pad = 0x80;
        update(&pad, 1);
        pad = 0x00;
        while (buf_len_ != 56) {
            update(&pad, 1);
        }

        for (int i = 7; i >= 0; i--) {
            unsigned char b = static_cast<unsigned char>((bit_count >> (i * 8)) & 0xff);
            update(&b, 1);
        }

        std::vector<unsigned char> hash(32);
        for (int i = 0; i < 8; i++) {
            hash[i * 4]     = static_cast<unsigned char>((state_[i] >> 24) & 0xff);
            hash[i * 4 + 1] = static_cast<unsigned char>((state_[i] >> 16) & 0xff);
            hash[i * 4 + 2] = static_cast<unsigned char>((state_[i] >> 8) & 0xff);
            hash[i * 4 + 3] = static_cast<unsigned char>(state_[i] & 0xff);
        }
        return hash;
    }

    static std::vector<unsigned char> hash(const unsigned char* data, size_t len) {
        SHA256 ctx;
        ctx.update(data, len);
        return ctx.finalize();
    }

    static std::vector<unsigned char> hash(const std::vector<unsigned char>& data) {
        return hash(data.data(), data.size());
    }

    static std::vector<unsigned char> hash(const std::string& s) {
        SHA256 ctx;
        ctx.update(s);
        return ctx.finalize();
    }

private:
    uint32_t state_[8];
    unsigned char buf_[64];
    size_t buf_len_;
    uint64_t count_;

    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t gamma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t gamma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    void transform(const unsigned char block[64]) {
        static const uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        uint32_t W[64];
        for (int i = 0; i < 16; i++) {
            W[i] = (uint32_t(block[i * 4]) << 24) |
                   (uint32_t(block[i * 4 + 1]) << 16) |
                   (uint32_t(block[i * 4 + 2]) << 8) |
                   uint32_t(block[i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            W[i] = gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16];
        }

        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + W[i];
            uint32_t t2 = sigma0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }
};

} // namespace internal
} // namespace nutcpp
