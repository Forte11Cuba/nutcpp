#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include <nlohmann/json.hpp>

namespace nutcpp {

struct Tag {
    std::string key;
    std::vector<std::string> values;

    Tag() = default;

    Tag(const std::string& key, const std::vector<std::string>& values)
        : key(key), values(values) {}

    // Construct from flat array: first element is key, rest are values
    explicit Tag(const std::vector<std::string>& arr) {
        if (arr.empty())
            throw std::invalid_argument("Tag cannot be empty");
        key = arr[0];
        values.assign(arr.begin() + 1, arr.end());
    }

    // Convert back to flat array ["key", "val1", "val2", ...]
    std::vector<std::string> to_array() const {
        std::vector<std::string> result;
        result.reserve(1 + values.size());
        result.push_back(key);
        result.insert(result.end(), values.begin(), values.end());
        return result;
    }
};

// JSON: serializes as flat array ["key", "val1", "val2"]
inline void to_json(nlohmann::json& j, const Tag& t) {
    j = t.to_array();
}

inline void from_json(const nlohmann::json& j, Tag& t) {
    auto arr = j.get<std::vector<std::string>>();
    t = Tag(arr);
}

} // namespace nutcpp
