#include "nutcpp/api/cashu_http_client.h"

#include <httplib.h>

#include <stdexcept>

using namespace std;

namespace nutcpp::api {

CashuHttpClient::CashuHttpClient(const string& mint_url)
    : client_(make_unique<httplib::Client>(mint_url)) {
    // Follow redirects (some mints use them).
    client_->set_follow_location(true);
    // Content type for all requests.
    client_->set_default_headers({{"Accept", "application/json"}});
}

CashuHttpClient::~CashuHttpClient() = default;

CashuHttpClient::CashuHttpClient(CashuHttpClient&&) noexcept = default;
CashuHttpClient& CashuHttpClient::operator=(CashuHttpClient&&) noexcept = default;

// ======================================================================
// Helper: handle HTTP response, check for errors, return parsed JSON.
// Mirrors DotNut CashuHttpClient.HandleResponse<T>.
// ======================================================================

static nlohmann::json handle_response(const httplib::Result& result) {
    if (!result) {
        throw runtime_error("HTTP request failed: " + to_string(static_cast<int>(result.error())));
    }

    auto& res = result.value();

    // HTTP 400 → CashuProtocolError from the mint.
    if (res.status == 400) {
        auto err = nlohmann::json::parse(res.body).get<CashuProtocolError>();
        throw CashuProtocolException(err);
    }

    // Any other non-2xx status.
    if (res.status < 200 || res.status >= 300) {
        throw runtime_error("HTTP " + to_string(res.status) + ": " + res.body);
    }

    return nlohmann::json::parse(res.body);
}

// ======================================================================
// Low-level JSON transport
// ======================================================================

nlohmann::json CashuHttpClient::get_json(const string& path) {
    auto result = client_->Get("/" + path);
    return handle_response(result);
}

nlohmann::json CashuHttpClient::post_json(const string& path, const nlohmann::json& body) {
    auto result = client_->Post("/" + path, body.dump(), "application/json");
    return handle_response(result);
}

// ======================================================================
// ICashuApi implementations — delegate to get_json/post_json
// ======================================================================

GetKeysResponse CashuHttpClient::get_keys() {
    return get_json("v1/keys").get<GetKeysResponse>();
}

GetKeysResponse CashuHttpClient::get_keys(const KeysetId& keyset_id) {
    return get_json("v1/keys/" + keyset_id.to_string()).get<GetKeysResponse>();
}

GetKeysetsResponse CashuHttpClient::get_keysets() {
    return get_json("v1/keysets").get<GetKeysetsResponse>();
}

PostSwapResponse CashuHttpClient::swap(const PostSwapRequest& request) {
    nlohmann::json j = request;
    return post_json("v1/swap", j).get<PostSwapResponse>();
}

GetInfoResponse CashuHttpClient::get_info() {
    return get_json("v1/info").get<GetInfoResponse>();
}

PostCheckStateResponse CashuHttpClient::check_state(const PostCheckStateRequest& request) {
    nlohmann::json j = request;
    return post_json("v1/checkstate", j).get<PostCheckStateResponse>();
}

PostRestoreResponse CashuHttpClient::restore(const PostRestoreRequest& request) {
    nlohmann::json j = request;
    return post_json("v1/restore", j).get<PostRestoreResponse>();
}

} // namespace nutcpp::api
