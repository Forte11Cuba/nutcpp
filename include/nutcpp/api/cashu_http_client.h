#pragma once

#include <string>
#include <memory>
#include <nlohmann/json.hpp>
#include "nutcpp/api/cashu_api.h"

namespace httplib { class Client; }

namespace nutcpp::api {

// HTTP implementation of ICashuApi using cpp-httplib.
// Synchronous (blocking) — matches cpp-httplib's default behavior.
//
// Usage:
//   CashuHttpClient client("https://testnut.cashu.space");
//   auto info = client.get_info();
//
class CashuHttpClient : public ICashuApi {
public:
    // Construct with mint base URL (e.g. "https://mint.host:3338").
    explicit CashuHttpClient(const std::string& mint_url);
    ~CashuHttpClient() override;

    // Non-copyable, movable.
    CashuHttpClient(const CashuHttpClient&) = delete;
    CashuHttpClient& operator=(const CashuHttpClient&) = delete;
    CashuHttpClient(CashuHttpClient&&) noexcept;
    CashuHttpClient& operator=(CashuHttpClient&&) noexcept;

    // NUT-01
    GetKeysResponse get_keys() override;
    GetKeysResponse get_keys(const KeysetId& keyset_id) override;

    // NUT-02
    GetKeysetsResponse get_keysets() override;

    // NUT-03
    PostSwapResponse swap(const PostSwapRequest& request) override;

    // NUT-06
    GetInfoResponse get_info() override;

    // NUT-07
    PostCheckStateResponse check_state(const PostCheckStateRequest& request) override;

    // NUT-09
    PostRestoreResponse restore(const PostRestoreRequest& request) override;

protected:
    nlohmann::json get_json(const std::string& path) override;
    nlohmann::json post_json(const std::string& path, const nlohmann::json& body) override;

private:
    std::unique_ptr<httplib::Client> client_;
};

} // namespace nutcpp::api
