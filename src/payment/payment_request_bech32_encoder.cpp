#include "nutcpp/payment/payment_request_bech32_encoder.h"
#include "bech32.h"
#include "nip19.h"
#include <stdexcept>
#include <cctype>

using namespace std;
using namespace nutcpp::internal;

namespace nutcpp::payment {

// ====== TLV write helpers (NUT-26: 1-byte tag + 2-byte BE length) ======

static void write_tlv(vector<uint8_t>& buf, uint8_t tag,
                       const uint8_t* data, size_t len) {
    if (len > 0xFFFF)
        throw invalid_argument("TLV value too long (max 65535 bytes)");
    buf.push_back(tag);
    buf.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(len & 0xFF));
    buf.insert(buf.end(), data, data + len);
}

static void write_tlv(vector<uint8_t>& buf, uint8_t tag,
                       const vector<uint8_t>& data) {
    write_tlv(buf, tag, data.data(), data.size());
}

static void write_tlv_utf8(vector<uint8_t>& buf, uint8_t tag, const string& str) {
    write_tlv(buf, tag, reinterpret_cast<const uint8_t*>(str.data()), str.size());
}

static void write_tag_tuple(vector<uint8_t>& buf, uint8_t tag,
                             const vector<string>& tuple) {
    size_t total = 0;
    for (auto& s : tuple) {
        if (s.size() > 255)
            throw invalid_argument("Tag tuple string too long (max 255 bytes)");
        total += 1 + s.size();
    }

    if (total > 65535)
        throw invalid_argument("Tag tuple total length exceeds 65535 bytes");

    buf.push_back(tag);
    buf.push_back(static_cast<uint8_t>((total >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(total & 0xFF));

    for (auto& s : tuple) {
        buf.push_back(static_cast<uint8_t>(s.size()));
        buf.insert(buf.end(), s.begin(), s.end());
    }
}

// ====== TLV encode sub-structures ======

static void encode_transport_tlv(vector<uint8_t>& buf,
                                  const PaymentRequestTransport& transport) {
    string type_lower = transport.type;
    for (auto& c : type_lower)
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

    if (type_lower == "post") {
        write_tlv(buf, 0x01, vector<uint8_t>{0x01});
        write_tlv_utf8(buf, 0x02, transport.target);

        if (transport.tags.has_value()) {
            for (auto& tag : transport.tags.value())
                write_tag_tuple(buf, 0x03, tag.to_array());
        }
    } else if (type_lower == "nostr") {
        write_tlv(buf, 0x01, vector<uint8_t>{0x00});

        auto nostr = decode_nostr(transport.target);
        write_tlv(buf, 0x02, nostr.pubkey);

        // Relay URLs as "r" tag tuples
        for (auto& relay : nostr.relays)
            write_tag_tuple(buf, 0x03, {"r", relay});

        // Other tags (e.g. "n" for NIPs)
        if (transport.tags.has_value()) {
            for (auto& tag : transport.tags.value())
                write_tag_tuple(buf, 0x03, tag.to_array());
        }
    } else {
        throw invalid_argument("Unknown transport type: " + transport.type);
    }
}

static void encode_nut10_tlv(vector<uint8_t>& buf,
                              const Nut10LockingCondition& nut10) {
    string kind_upper = nut10.kind;
    for (auto& c : kind_upper)
        c = static_cast<char>(toupper(static_cast<unsigned char>(c)));

    uint8_t kind_byte;
    if (kind_upper == "P2PK") kind_byte = 0x00;
    else if (kind_upper == "HTLC") kind_byte = 0x01;
    else throw invalid_argument("Unknown nut10 kind: " + nut10.kind);

    write_tlv(buf, 0x01, vector<uint8_t>{kind_byte});
    write_tlv_utf8(buf, 0x02, nut10.data);

    if (nut10.tags.has_value()) {
        for (auto& tag : nut10.tags.value())
            write_tag_tuple(buf, 0x03, tag.to_array());
    }
}

// ====== TLV decode helpers ======

static vector<string> decode_tag_tuple(const uint8_t* data, size_t len) {
    vector<string> result;
    size_t offset = 0;
    while (offset < len) {
        uint8_t str_len = data[offset++];
        if (offset + str_len > len)
            throw invalid_argument("Invalid tag tuple: data too short");
        result.emplace_back(reinterpret_cast<const char*>(data + offset), str_len);
        offset += str_len;
    }
    return result;
}

static PaymentRequestTransport decode_transport_tlv(const uint8_t* data, size_t len) {
    PaymentRequestTransport transport;
    size_t offset = 0;
    vector<uint8_t> target_bytes;
    vector<vector<string>> all_tuples;

    while (offset < len) {
        if (offset + 3 > len)
            throw invalid_argument("Transport TLV too short");
        uint8_t tag = data[offset];
        uint16_t length = (static_cast<uint16_t>(data[offset + 1]) << 8) | data[offset + 2];
        offset += 3;
        if (offset + length > len)
            throw invalid_argument("Transport TLV value too short");

        switch (tag) {
            case 0x01:
                if (data[offset] == 0x00) transport.type = "nostr";
                else if (data[offset] == 0x01) transport.type = "post";
                else throw invalid_argument("Unknown transport kind");
                break;
            case 0x02:
                target_bytes.assign(data + offset, data + offset + length);
                break;
            case 0x03:
                all_tuples.push_back(decode_tag_tuple(data + offset, length));
                break;
        }
        offset += length;
    }

    if (transport.type == "nostr" && !target_bytes.empty()) {
        vector<string> relays;
        vector<vector<string>> non_relay_tuples;

        for (auto& tuple : all_tuples) {
            if (tuple.size() >= 2 && tuple[0] == "r")
                relays.push_back(tuple[1]);
            else
                non_relay_tuples.push_back(tuple);
        }

        transport.target = encode_nprofile(target_bytes, relays);

        if (!non_relay_tuples.empty()) {
            vector<Tag> tags;
            for (auto& tuple : non_relay_tuples)
                tags.emplace_back(tuple);
            transport.tags = tags;
        }
    } else if (transport.type == "post" && !target_bytes.empty()) {
        transport.target = string(reinterpret_cast<const char*>(target_bytes.data()),
                                  target_bytes.size());

        if (!all_tuples.empty()) {
            vector<Tag> tags;
            for (auto& tuple : all_tuples)
                tags.emplace_back(tuple);
            transport.tags = tags;
        }
    }

    return transport;
}

static Nut10LockingCondition decode_nut10_tlv(const uint8_t* data, size_t len) {
    Nut10LockingCondition nut10;
    size_t offset = 0;
    vector<Tag> tags;

    while (offset < len) {
        if (offset + 3 > len)
            throw invalid_argument("Nut10 TLV too short");
        uint8_t tag = data[offset];
        uint16_t length = (static_cast<uint16_t>(data[offset + 1]) << 8) | data[offset + 2];
        offset += 3;
        if (offset + length > len)
            throw invalid_argument("Nut10 TLV value too short");

        switch (tag) {
            case 0x01:
                if (data[offset] == 0x00) nut10.kind = "P2PK";
                else if (data[offset] == 0x01) nut10.kind = "HTLC";
                else throw invalid_argument("Unknown nut10 kind");
                break;
            case 0x02:
                nut10.data = string(reinterpret_cast<const char*>(data + offset), length);
                break;
            case 0x03: {
                auto tuple = decode_tag_tuple(data + offset, length);
                tags.emplace_back(tuple);
                break;
            }
        }
        offset += length;
    }

    if (!tags.empty())
        nut10.tags = tags;

    return nut10;
}

// ====== Encode (PaymentRequest -> "CREQB1...") ======

string PaymentRequestBech32Encoder::encode(const PaymentRequest& request) {
    vector<uint8_t> tlv;

    // Fields in tag order (matching DotNut EncodeTLV)
    if (request.payment_id.has_value())
        write_tlv_utf8(tlv, 0x01, request.payment_id.value());

    if (request.amount.has_value()) {
        uint8_t amount_bytes[8];
        uint64_t a = request.amount.value();
        for (int i = 7; i >= 0; --i) {
            amount_bytes[i] = static_cast<uint8_t>(a & 0xFF);
            a >>= 8;
        }
        write_tlv(tlv, 0x02, amount_bytes, 8);
    }

    if (request.unit.has_value()) {
        string unit_lower = request.unit.value();
        for (auto& c : unit_lower)
            c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        if (unit_lower == "sat") {
            write_tlv(tlv, 0x03, vector<uint8_t>{0x00});
        } else {
            write_tlv_utf8(tlv, 0x03, unit_lower);
        }
    }

    if (request.single_use.has_value()) {
        uint8_t val = request.single_use.value() ? 0x01 : 0x00;
        write_tlv(tlv, 0x04, &val, 1);
    }

    if (request.mints.has_value()) {
        for (auto& mint : request.mints.value())
            write_tlv_utf8(tlv, 0x05, mint);
    }

    if (request.description.has_value())
        write_tlv_utf8(tlv, 0x06, request.description.value());

    for (auto& transport : request.transports) {
        vector<uint8_t> sub;
        encode_transport_tlv(sub, transport);
        write_tlv(tlv, 0x07, sub);
    }

    if (request.nut10.has_value()) {
        vector<uint8_t> sub;
        encode_nut10_tlv(sub, request.nut10.value());
        write_tlv(tlv, 0x08, sub);
    }

    auto data_5bit = convert_bits(tlv, 8, 5, true);
    auto encoded = bech32_encode_raw("creqb", data_5bit, Bech32Type::BECH32M);

    // Uppercase for QR code compatibility (spec recommendation, DotNut behavior)
    string upper;
    upper.reserve(encoded.size());
    for (auto c : encoded)
        upper += static_cast<char>(toupper(static_cast<unsigned char>(c)));
    return upper;
}

// ====== Decode ("CREQB1..." -> PaymentRequest) ======

PaymentRequest PaymentRequestBech32Encoder::decode(const string& creqb) {
    Bech32Type type;
    auto data_5bit = bech32_decode_raw(creqb, "creqb", type);

    if (type != Bech32Type::BECH32M)
        throw invalid_argument("Invalid creqB: expected Bech32m encoding");

    auto tlv = convert_bits(data_5bit, 5, 8, false);

    PaymentRequest r;
    size_t offset = 0;
    vector<string> mints;

    while (offset < tlv.size()) {
        if (offset + 3 > tlv.size())
            throw invalid_argument("creqB TLV too short");
        uint8_t tag = tlv[offset];
        uint16_t length = (static_cast<uint16_t>(tlv[offset + 1]) << 8) | tlv[offset + 2];
        offset += 3;
        if (offset + length > tlv.size())
            throw invalid_argument("creqB TLV value too short");

        const uint8_t* value = tlv.data() + offset;

        switch (tag) {
            case 0x01:
                r.payment_id = string(reinterpret_cast<const char*>(value), length);
                break;
            case 0x02: {
                uint64_t amount = 0;
                for (uint16_t i = 0; i < length; ++i)
                    amount = (amount << 8) | value[i];
                r.amount = amount;
                break;
            }
            case 0x03:
                if (length == 1 && value[0] == 0x00)
                    r.unit = "sat";
                else
                    r.unit = string(reinterpret_cast<const char*>(value), length);
                break;
            case 0x04:
                r.single_use = (length == 1 && value[0] == 0x01);
                break;
            case 0x05:
                mints.emplace_back(reinterpret_cast<const char*>(value), length);
                break;
            case 0x06:
                r.description = string(reinterpret_cast<const char*>(value), length);
                break;
            case 0x07:
                r.transports.push_back(decode_transport_tlv(value, length));
                break;
            case 0x08:
                r.nut10 = decode_nut10_tlv(value, length);
                break;
        }
        offset += length;
    }

    if (!mints.empty())
        r.mints = mints;

    return r;
}

} // namespace nutcpp::payment
