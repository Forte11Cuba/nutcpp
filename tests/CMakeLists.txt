add_executable(nutcpp_tests
    test_types.cpp
    test_keyset.cpp
    test_crypto.cpp
    test_base64_url.cpp
    test_encoding.cpp
    test_api_models.cpp
    test_integration.cpp
    test_wallet.cpp
    test_p2pk.cpp
    test_sig_all.cpp
    test_p2bk.cpp
    test_nut13.cpp
    test_payment.cpp
    test_blinding_helper.cpp
)

target_link_libraries(nutcpp_tests
    PRIVATE
        nutcpp
        Catch2::Catch2WithMain
)

include(CTest)
include(Catch)
catch_discover_tests(nutcpp_tests)
