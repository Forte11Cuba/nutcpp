add_executable(nutcpp_tests
    test_types.cpp
    test_keyset.cpp
    test_crypto.cpp
    test_base64_url.cpp
    test_encoding.cpp
    test_api_models.cpp
    test_integration.cpp
)

target_link_libraries(nutcpp_tests
    PRIVATE
        nutcpp
        Catch2::Catch2WithMain
)

include(CTest)
include(Catch)
catch_discover_tests(nutcpp_tests)
