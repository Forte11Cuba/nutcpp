#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>

namespace nutcpp {

// Base64 URL-safe encoding/decoding (RFC 4648 §5).
// Encoding omits padding. Decoding accepts both padded and unpadded input.
class Base64Url {
public:
    static std::string encode(const unsigned char* data, size_t len) {
        static const char table[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        std::string result;
        result.reserve((len + 2) / 3 * 4);

        size_t i = 0;
        for (; i + 2 < len; i += 3) {
            uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                         (static_cast<uint32_t>(data[i + 1]) << 8) |
                         static_cast<uint32_t>(data[i + 2]);
            result += table[(n >> 18) & 0x3F];
            result += table[(n >> 12) & 0x3F];
            result += table[(n >> 6) & 0x3F];
            result += table[n & 0x3F];
        }

        if (i + 1 == len) {
            uint32_t n = static_cast<uint32_t>(data[i]) << 16;
            result += table[(n >> 18) & 0x3F];
            result += table[(n >> 12) & 0x3F];
        } else if (i + 2 == len) {
            uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                         (static_cast<uint32_t>(data[i + 1]) << 8);
            result += table[(n >> 18) & 0x3F];
            result += table[(n >> 12) & 0x3F];
            result += table[(n >> 6) & 0x3F];
        }

        return result; // No padding per spec
    }

    static std::string encode(const std::vector<unsigned char>& data) {
        return encode(data.data(), data.size());
    }

    static std::string encode(const std::string& str) {
        return encode(reinterpret_cast<const unsigned char*>(str.data()), str.size());
    }

    static std::vector<unsigned char> decode(const std::string& input) {
        // Decode table: maps ASCII char to 6-bit value, 0xFF = invalid
        static const unsigned char dtable[256] = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,  62,0xFF,  62,0xFF,  63,
            //                                                    +         -         /
              52,  53,  54,  55,  56,  57,  58,  59,   60,  61,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            // 0    1    2    3    4    5    6    7      8    9              =
            0xFF,   0,   1,   2,   3,   4,   5,   6,    7,   8,   9,  10,  11,  12,  13,  14,
            //   A    B    C    D    E    F    G      H    I    J    K    L    M    N    O
              15,  16,  17,  18,  19,  20,  21,  22,   23,  24,  25,0xFF,0xFF,0xFF,0xFF,  63,
            // P    Q    R    S    T    U    V    W      X    Y    Z                        _
            0xFF,  26,  27,  28,  29,  30,  31,  32,   33,  34,  35,  36,  37,  38,  39,  40,
            //   a    b    c    d    e    f    g      h    i    j    k    l    m    n    o
              41,  42,  43,  44,  45,  46,  47,  48,   49,  50,  51,0xFF,0xFF,0xFF,0xFF,0xFF,
            // p    q    r    s    t    u    v    w      x    y    z
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        };

        // Strip padding
        size_t len = input.size();
        while (len > 0 && input[len - 1] == '=') --len;

        std::vector<unsigned char> result;
        result.reserve(len * 3 / 4);

        uint32_t buf = 0;
        int bits = 0;

        for (size_t i = 0; i < len; ++i) {
            unsigned char c = static_cast<unsigned char>(input[i]);
            unsigned char val = dtable[c];
            if (val == 0xFF)
                throw std::invalid_argument(
                    std::string("Invalid base64url character: '") + input[i] + "'");

            buf = (buf << 6) | val;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                result.push_back(static_cast<unsigned char>((buf >> bits) & 0xFF));
            }
        }

        return result;
    }

    static std::string decode_to_string(const std::string& input) {
        auto bytes = decode(input);
        return std::string(bytes.begin(), bytes.end());
    }
};

} // namespace nutcpp
