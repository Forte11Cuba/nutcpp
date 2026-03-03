add_executable(nutcpp_tests
    test_types.cpp
    # test_crypto.cpp
    # test_keyset.cpp
)

target_link_libraries(nutcpp_tests
    PRIVATE
        nutcpp
        Catch2::Catch2WithMain
)

include(CTest)
include(Catch)
catch_discover_tests(nutcpp_tests)
