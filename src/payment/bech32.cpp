#include "bech32.h"
#include <stdexcept>
#include <algorithm>
#include <cctype>

using namespace std;

namespace nutcpp {
namespace internal {

// ====== Constants ======

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Reverse lookup: ASCII char -> 5-bit value, 0xFF = invalid
static const uint8_t CHARSET_REV[128] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    //  0     1     2     3     4     5     6     7
       15, 0xFF,  10,  17,  21,  20,  26,  30,
    //  8     9
        7,    5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    //        a     b     c     d     e     f     g
    0xFF,  29, 0xFF,  24,  13,  25,   9,    8,
    //  h     i     j     k     l     m     n     o
       23, 0xFF,  18,  22,  31,  27,  19, 0xFF,
    //  p     q     r     s     t     u     v     w
        1,    0,    3,  16,  11,  28,  12,  14,
    //  x     y     z
        6,    4,    2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const uint32_t BECH32_CONST = 1;
static const uint32_t BECH32M_CONST = 0x2bc830a3;

static const uint32_t GEN[5] = {
    0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
};

// ====== Polymod ======

static uint32_t polymod(const vector<uint8_t>& values) {
    uint32_t chk = 1;
    for (auto v : values) {
        uint32_t top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ v;
        for (int i = 0; i < 5; ++i) {
            if ((top >> i) & 1)
                chk ^= GEN[i];
        }
    }
    return chk;
}

// ====== HRP expand ======

static vector<uint8_t> hrp_expand(const string& hrp) {
    vector<uint8_t> ret;
    ret.reserve(hrp.size() * 2 + 1);
    for (auto c : hrp)
        ret.push_back(static_cast<uint8_t>(c) >> 5);
    ret.push_back(0);
    for (auto c : hrp)
        ret.push_back(static_cast<uint8_t>(c) & 31);
    return ret;
}

// ====== Checksum ======

static uint32_t encoding_constant(Bech32Type type) {
    return type == Bech32Type::BECH32M ? BECH32M_CONST : BECH32_CONST;
}

static vector<uint8_t> create_checksum(const string& hrp,
                                        const vector<uint8_t>& data,
                                        Bech32Type type) {
    auto values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    // Append 6 zeros for checksum computation
    values.resize(values.size() + 6, 0);
    uint32_t pm = polymod(values) ^ encoding_constant(type);
    vector<uint8_t> ret(6);
    for (int i = 0; i < 6; ++i)
        ret[i] = static_cast<uint8_t>((pm >> (5 * (5 - i))) & 31);
    return ret;
}

static bool verify_checksum(const string& hrp,
                             const vector<uint8_t>& data,
                             Bech32Type& out_type) {
    auto values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    uint32_t pm = polymod(values);
    if (pm == BECH32_CONST) {
        out_type = Bech32Type::BECH32;
        return true;
    }
    if (pm == BECH32M_CONST) {
        out_type = Bech32Type::BECH32M;
        return true;
    }
    return false;
}

// ====== Encode ======

string bech32_encode_raw(const string& hrp,
                          const vector<uint8_t>& data_5bit,
                          Bech32Type type) {
    auto checksum = create_checksum(hrp, data_5bit, type);

    string result;
    result.reserve(hrp.size() + 1 + data_5bit.size() + 6);

    // HRP (lowercase)
    for (auto c : hrp)
        result += static_cast<char>(tolower(static_cast<unsigned char>(c)));

    result += '1'; // separator

    // Data + checksum mapped through charset
    for (auto v : data_5bit)
        result += CHARSET[v];
    for (auto v : checksum)
        result += CHARSET[v];

    return result;
}

// ====== Decode ======

vector<uint8_t> bech32_decode_raw(const string& bech,
                                   const string& expected_hrp,
                                   Bech32Type& out_type) {
    // Reject mixed case
    bool has_lower = false, has_upper = false;
    for (auto c : bech) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        if (c >= 'A' && c <= 'Z') has_upper = true;
    }
    if (has_lower && has_upper)
        throw invalid_argument("Bech32: mixed case");

    // Lowercase for processing
    string lower;
    lower.reserve(bech.size());
    for (auto c : bech)
        lower += static_cast<char>(tolower(static_cast<unsigned char>(c)));

    // Find last '1' separator
    auto pos = lower.rfind('1');
    if (pos == string::npos || pos < 1)
        throw invalid_argument("Bech32: missing separator '1'");
    if (pos + 7 > lower.size())
        throw invalid_argument("Bech32: data part too short");
    // No strict length limit (payment requests exceed 90 chars)

    // Verify HRP
    string hrp_lower;
    hrp_lower.reserve(expected_hrp.size());
    for (auto c : expected_hrp)
        hrp_lower += static_cast<char>(tolower(static_cast<unsigned char>(c)));

    string found_hrp = lower.substr(0, pos);
    if (found_hrp != hrp_lower)
        throw invalid_argument("Bech32: HRP mismatch, expected '" +
                                hrp_lower + "', got '" + found_hrp + "'");

    // Decode data characters
    vector<uint8_t> data;
    data.reserve(lower.size() - pos - 1);
    for (size_t i = pos + 1; i < lower.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(lower[i]);
        if (c >= 128)
            throw invalid_argument("Bech32: non-ASCII character");
        uint8_t val = CHARSET_REV[c];
        if (val == 0xFF)
            throw invalid_argument("Bech32: invalid character");
        data.push_back(val);
    }

    // Verify checksum
    if (!verify_checksum(found_hrp, data, out_type))
        throw invalid_argument("Bech32: invalid checksum");

    // Strip 6-byte checksum
    data.resize(data.size() - 6);
    return data;
}

// ====== Convert bits ======

vector<uint8_t> convert_bits(const uint8_t* data, size_t len,
                              int from_bits, int to_bits, bool pad) {
    int acc = 0;
    int bits = 0;
    int maxv = (1 << to_bits) - 1;
    vector<uint8_t> ret;
    ret.reserve((len * from_bits + to_bits - 1) / to_bits);

    for (size_t i = 0; i < len; ++i) {
        int value = data[i];
        if ((value >> from_bits) != 0)
            throw invalid_argument("convert_bits: value exceeds from_bits");
        acc = (acc << from_bits) | value;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            ret.push_back(static_cast<uint8_t>((acc >> bits) & maxv));
        }
    }

    if (pad) {
        if (bits > 0)
            ret.push_back(static_cast<uint8_t>((acc << (to_bits - bits)) & maxv));
    } else if (bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0) {
        throw invalid_argument("convert_bits: invalid padding");
    }

    return ret;
}

vector<uint8_t> convert_bits(const vector<uint8_t>& data,
                              int from_bits, int to_bits, bool pad) {
    return convert_bits(data.data(), data.size(), from_bits, to_bits, pad);
}

} // namespace internal
} // namespace nutcpp
