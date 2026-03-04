add_library(nutcpp
    types/pub_key.cpp
    types/priv_key.cpp
    types/secret.cpp
    types/keyset_id.cpp
    types/keyset.cpp
    crypto/cashu.cpp
    encoding/token_v4_encoder.cpp
    encoding/token_helper.cpp
    api/cashu_http_client.cpp
    wallet/fee_helper.cpp
    wallet/proof_selector.cpp
    nuts/nut10_secret.cpp
    nuts/p2pk.cpp
)

target_include_directories(nutcpp
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

find_package(OpenSSL REQUIRED)

target_link_libraries(nutcpp
    PUBLIC
        secp256k1
        nlohmann_json::nlohmann_json
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
)

# cpp-httplib is header-only; add include path and OPENSSL define.
target_include_directories(nutcpp
    PRIVATE
        ${httplib_SOURCE_DIR}
)
target_compile_definitions(nutcpp
    PRIVATE
        CPPHTTPLIB_OPENSSL_SUPPORT
)
