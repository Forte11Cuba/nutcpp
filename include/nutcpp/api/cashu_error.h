#pragma once

#include <string>
#include <stdexcept>
#include <nlohmann/json.hpp>

namespace nutcpp::api {

// Error returned by the mint on protocol violations (HTTP 400).
// See error_codes.md for the full list of codes.
struct CashuProtocolError {
    std::string detail;
    int code = 0;
};

inline void to_json(nlohmann::json& j, const CashuProtocolError& e) {
    j = {{"detail", e.detail}, {"code", e.code}};
}

inline void from_json(const nlohmann::json& j, CashuProtocolError& e) {
    j.at("detail").get_to(e.detail);
    j.at("code").get_to(e.code);
}

// Exception wrapping a CashuProtocolError for throw/catch flow.
class CashuProtocolException : public std::runtime_error {
public:
    explicit CashuProtocolException(const CashuProtocolError& error)
        : std::runtime_error(error.detail), error_(error) {}

    const CashuProtocolError& error() const { return error_; }

private:
    CashuProtocolError error_;
};

} // namespace nutcpp::api
