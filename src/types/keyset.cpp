#include "nutcpp/types/keyset.h"
#include "nutcpp/encoding/convert_utils.h"
#include "../crypto/sha256.h"

using namespace std;

namespace nutcpp {

KeysetId Keyset::get_keyset_id(
    uint8_t version,
    const optional<string>& unit,
    optional<uint64_t> input_fee_ppk,
    const optional<string>& final_expiry
) const {
    if (empty()) {
        throw runtime_error("Keyset cannot be empty");
    }

    internal::SHA256 sha;

    switch (version) {
        case 0x00: {
            // V1 (deprecated): concat all pubkey bytes sorted by amount, SHA256, take first 14 hex chars
            // std::map already sorts by key (amount) in ascending order
            for (const auto& [amount, pubkey] : *this) {
                auto bytes = hex_to_bytes(pubkey.to_hex());
                sha.update(bytes);
            }

            auto hash = sha.finalize();
            string hash_hex = bytes_to_hex(hash.data(), hash.size());

            // version byte "00" + first 14 chars of hash hex = 16 chars total
            return KeysetId{"00" + hash_hex.substr(0, 14)};
        }

        case 0x01: {
            // V2: build preimage string "amount:pubkey_hex,...|unit:X|input_fee_ppk:N|final_expiry:T"
            if (!unit.has_value() || unit->empty()) {
                throw runtime_error("Unit parameter is required for keyset ID version 0x01");
            }

            // "1:03a40f...,2:03fd4c...,4:02648e..."
            string preimage;
            bool first = true;
            for (const auto& [amount, pubkey] : *this) {
                if (!first) preimage += ",";
                preimage += to_string(amount) + ":" + pubkey.to_hex();
                first = false;
            }

            // "|unit:sat"
            preimage += "|unit:" + *unit;

            // "|input_fee_ppk:100" (only if specified and non-zero)
            if (input_fee_ppk.has_value() && *input_fee_ppk != 0) {
                preimage += "|input_fee_ppk:" + to_string(*input_fee_ppk);
            }

            // "|final_expiry:2059210353" (only if specified and non-empty)
            if (final_expiry.has_value() && !final_expiry->empty()) {
                preimage += "|final_expiry:" + *final_expiry;
            }

            sha.update(preimage);
            auto hash = sha.finalize();
            string hash_hex = bytes_to_hex(hash.data(), hash.size());

            // version byte "01" + full hash hex = 66 chars total
            return KeysetId{"01" + hash_hex};
        }

        default:
            throw runtime_error("Unsupported keyset version: " + to_string(version));
    }
}

bool Keyset::verify_keyset_id(
    const KeysetId& keyset_id,
    const optional<string>& unit,
    optional<uint64_t> input_fee_ppk,
    const optional<string>& final_expiry
) const {
    uint8_t version = keyset_id.get_version();
    string derived = get_keyset_id(version, unit, input_fee_ppk, final_expiry).to_string();
    string presented = keyset_id.to_string();

    if (presented.size() > derived.size()) return false;

    // Exact match or prefix match (for truncated IDs)
    return derived == presented || derived.substr(0, presented.size()) == presented;
}

} // namespace nutcpp
