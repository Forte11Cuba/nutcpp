#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include "nutcpp/api/cashu_error.h"
#include "nutcpp/api_models/keys_response.h"
#include "nutcpp/api_models/keysets_response.h"
#include "nutcpp/api_models/swap_models.h"
#include "nutcpp/api_models/mint_models.h"
#include "nutcpp/api_models/melt_models.h"
#include "nutcpp/api_models/info_response.h"
#include "nutcpp/api_models/check_state_models.h"
#include "nutcpp/api_models/restore_models.h"
#include "nutcpp/types/keyset_id.h"

namespace nutcpp::api {

// Abstract interface for the Cashu mint API (NUT-01 to NUT-09).
// Mirrors DotNut ICashuApi.cs. Synchronous — no async/await in C++.
class ICashuApi {
public:
    virtual ~ICashuApi() = default;

    // NUT-01: GET /v1/keys — active keysets with public keys.
    virtual GetKeysResponse get_keys() = 0;

    // NUT-02: GET /v1/keys/{keyset_id} — keys for a specific keyset.
    virtual GetKeysResponse get_keys(const KeysetId& keyset_id) = 0;

    // NUT-02: GET /v1/keysets — all keysets (active and inactive).
    virtual GetKeysetsResponse get_keysets() = 0;

    // NUT-03: POST /v1/swap — exchange proofs for new blind signatures.
    virtual PostSwapResponse swap(const PostSwapRequest& request) = 0;

    // NUT-04: POST /v1/mint/quote/{method} — request a mint quote.
    // Template: TRequest/TResponse vary by method (bolt11, bolt12).
    template <typename TRequest, typename TResponse>
    TResponse create_mint_quote(const std::string& method, const TRequest& request) {
        nlohmann::json req_json = request;
        auto res_json = post_json("v1/mint/quote/" + method, req_json);
        return res_json.template get<TResponse>();
    }

    // NUT-04: GET /v1/mint/quote/{method}/{quote_id} — check mint quote state.
    template <typename TResponse>
    TResponse check_mint_quote(const std::string& method, const std::string& quote_id) {
        auto res_json = get_json("v1/mint/quote/" + method + "/" + quote_id);
        return res_json.template get<TResponse>();
    }

    // NUT-04: POST /v1/mint/{method} — mint tokens with a paid quote.
    template <typename TRequest, typename TResponse>
    TResponse mint(const std::string& method, const TRequest& request) {
        nlohmann::json req_json = request;
        auto res_json = post_json("v1/mint/" + method, req_json);
        return res_json.template get<TResponse>();
    }

    // NUT-05: POST /v1/melt/quote/{method} — request a melt quote.
    template <typename TRequest, typename TResponse>
    TResponse create_melt_quote(const std::string& method, const TRequest& request) {
        nlohmann::json req_json = request;
        auto res_json = post_json("v1/melt/quote/" + method, req_json);
        return res_json.template get<TResponse>();
    }

    // NUT-05: GET /v1/melt/quote/{method}/{quote_id} — check melt quote state.
    template <typename TResponse>
    TResponse check_melt_quote(const std::string& method, const std::string& quote_id) {
        auto res_json = get_json("v1/melt/quote/" + method + "/" + quote_id);
        return res_json.template get<TResponse>();
    }

    // NUT-05: POST /v1/melt/{method} — melt tokens (pay invoice).
    template <typename TRequest, typename TResponse>
    TResponse melt(const std::string& method, const TRequest& request) {
        nlohmann::json req_json = request;
        auto res_json = post_json("v1/melt/" + method, req_json);
        return res_json.template get<TResponse>();
    }

    // NUT-06: GET /v1/info — mint information.
    virtual GetInfoResponse get_info() = 0;

    // NUT-07: POST /v1/checkstate — check proof states.
    virtual PostCheckStateResponse check_state(const PostCheckStateRequest& request) = 0;

    // NUT-09: POST /v1/restore — recover blind signatures.
    virtual PostRestoreResponse restore(const PostRestoreRequest& request) = 0;

protected:
    // Low-level JSON transport — implemented by subclasses (HTTP, mock, etc.).
    // These enable the template methods above without virtual templates.
    virtual nlohmann::json get_json(const std::string& path) = 0;
    virtual nlohmann::json post_json(const std::string& path, const nlohmann::json& body) = 0;
};

} // namespace nutcpp::api
