add_library(nutcpp
    types/pub_key.cpp
    types/priv_key.cpp
    types/secret.cpp
    types/keyset_id.cpp
    types/keyset.cpp
    # crypto/cashu.cpp
)

target_include_directories(nutcpp
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(nutcpp
    PUBLIC
        secp256k1
        nlohmann_json::nlohmann_json
)
