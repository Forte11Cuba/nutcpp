#include "nutcpp/api/cashu_http_client.h"

#include <httplib.h>

#include <stdexcept>

using namespace std;

namespace nutcpp::api {

CashuHttpClient::CashuHttpClient(const string& mint_url)
    : client_(make_unique<httplib::Client>(mint_url)) {
    client_->set_connection_timeout(10, 0);
    client_->set_write_timeout(10, 0);
    // Read timeout is long: NUT-05 melt can block while a Lightning payment
    // completes, which may take a long time. Spec says "use no or very long timeout".
    client_->set_read_timeout(120, 0);
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
        throw runtime_error("HTTP request failed: " + httplib::to_string(result.error()));
    }

    auto& res = result.value();

    // HTTP 400 → CashuProtocolError from the mint.
    if (res.status == 400) {
        try {
            auto err = nlohmann::json::parse(res.body).get<CashuProtocolError>();
            throw CashuProtocolException(err);
        } catch (const nlohmann::json::exception&) {
            throw runtime_error("HTTP 400 with non-Cashu error payload: " + res.body);
        }
    }

    // Any other non-2xx status.
    if (res.status < 200 || res.status >= 300) {
        throw runtime_error("HTTP " + to_string(res.status) + ": " + res.body);
    }

    try {
        return nlohmann::json::parse(res.body);
    } catch (const nlohmann::json::exception& e) {
        throw runtime_error("Invalid JSON in HTTP " + to_string(res.status) + " response: " + string(e.what()));
    }
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
