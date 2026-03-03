#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <nlohmann/json.hpp>

namespace nutcpp {

class KeysetId {
public:
    // Construct from hex string. Valid lengths: 16 (v1/v2 short), 66 (v2 full), 12 (legacy)
    explicit KeysetId(const std::string& id);

    // Hex string representation
    const std::string& to_string() const { return id_; }

    // First byte as version number (e.g. 0x00 = v1, 0x02 = v2)
    uint8_t get_version() const;

    // Convert hex to raw bytes
    std::vector<unsigned char> get_bytes() const;

    // Comparison (case-insensitive hex)
    bool operator==(const KeysetId& other) const;
    bool operator!=(const KeysetId& other) const { return !(*this == other); }

    // For use as map key
    bool operator<(const KeysetId& other) const;

private:
    std::string id_;
};

// JSON: serializes as hex string
void to_json(nlohmann::json& j, const KeysetId& kid);
void from_json(const nlohmann::json& j, KeysetId& kid);

} // namespace nutcpp
