#include "nip19.h"
#include "bech32.h"
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <cctype>

using namespace std;

namespace nutcpp {
namespace internal {

// ====== Decode npub ======

vector<uint8_t> decode_npub(const string& npub) {
    Bech32Type type;
    auto data_5bit = bech32_decode_raw(npub, "npub", type);

    if (type != Bech32Type::BECH32)
        throw invalid_argument("Invalid npub: expected BECH32 encoding");

    auto pubkey = convert_bits(data_5bit, 5, 8, false);
    if (pubkey.size() != 32)
        throw invalid_argument("Invalid npub: expected 32 bytes, got " +
                                to_string(pubkey.size()));
    return pubkey;
}

// ====== Decode nprofile ======

NprofileData decode_nprofile(const string& nprofile) {
    Bech32Type type;
    auto data_5bit = bech32_decode_raw(nprofile, "nprofile", type);

    if (type != Bech32Type::BECH32)
        throw invalid_argument("Invalid nprofile: expected BECH32 encoding");

    auto tlv_data = convert_bits(data_5bit, 5, 8, false);

    vector<uint8_t> pubkey;
    vector<string> relays;
    size_t offset = 0;

    while (offset < tlv_data.size()) {
        if (offset + 2 > tlv_data.size())
            throw invalid_argument("Nprofile TLV: data too short");

        uint8_t tag = tlv_data[offset];
        uint8_t length = tlv_data[offset + 1];
        offset += 2;

        if (offset + length > tlv_data.size())
            throw invalid_argument("Nprofile TLV: value too short, expected " +
                                    to_string(length) + " bytes");

        switch (tag) {
            case 0x00: // pubkey
                if (length != 32)
                    throw invalid_argument("Nprofile: invalid pubkey length " +
                                            to_string(length));
                pubkey.assign(tlv_data.begin() + offset,
                              tlv_data.begin() + offset + 32);
                break;
            case 0x01: // relay
                relays.emplace_back(
                    reinterpret_cast<const char*>(tlv_data.data() + offset),
                    length);
                break;
            default:
                // Unknown tags: skip (forward compatibility)
                break;
        }

        offset += length;
    }

    if (pubkey.empty())
        throw invalid_argument("Nprofile: missing required pubkey");

    return {pubkey, relays};
}

// ====== Decode nostr (dispatch) ======

static bool starts_with_ci(const string& str, const string& prefix) {
    if (str.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (tolower(static_cast<unsigned char>(str[i])) !=
            tolower(static_cast<unsigned char>(prefix[i])))
            return false;
    }
    return true;
}

NprofileData decode_nostr(const string& str) {
    if (starts_with_ci(str, "nprofile"))
        return decode_nprofile(str);

    // npub: wrap in NprofileData with empty relays
    auto pubkey = decode_npub(str);
    return {pubkey, {}};
}

// ====== Encode nprofile ======

string encode_nprofile(const uint8_t* pubkey, size_t pubkey_len,
                        const vector<string>& relays) {
    if (pubkey_len != 32)
        throw invalid_argument("encode_nprofile: expected 32-byte pubkey, got " +
                                to_string(pubkey_len));

    // Build TLV: tag (1 byte) + length (1 byte) + value
    // Pubkey: T=0x00, L=32, V=<32 bytes>
    size_t total_size = 34; // 1 + 1 + 32
    for (auto& relay : relays) {
        if (relay.size() > 255)
            throw invalid_argument("encode_nprofile: relay URL too long (max 255 bytes)");
        total_size += 2 + relay.size(); // 1 + 1 + len
    }

    vector<uint8_t> tlv_data;
    tlv_data.reserve(total_size);

    // Write pubkey
    tlv_data.push_back(0x00);
    tlv_data.push_back(32);
    tlv_data.insert(tlv_data.end(), pubkey, pubkey + 32);

    // Write relays
    for (auto& relay : relays) {
        tlv_data.push_back(0x01);
        tlv_data.push_back(static_cast<uint8_t>(relay.size()));
        tlv_data.insert(tlv_data.end(), relay.begin(), relay.end());
    }

    // Convert 8-bit -> 5-bit with padding
    auto data_5bit = convert_bits(tlv_data, 8, 5, true);

    // Encode as Bech32 (not Bech32m) with HRP "nprofile"
    return bech32_encode_raw("nprofile", data_5bit, Bech32Type::BECH32);
}

string encode_nprofile(const vector<uint8_t>& pubkey,
                        const vector<string>& relays) {
    return encode_nprofile(pubkey.data(), pubkey.size(), relays);
}

} // namespace internal
} // namespace nutcpp
