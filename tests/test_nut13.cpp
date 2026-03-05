#include <catch2/catch_test_macros.hpp>
#include "nutcpp/nuts/nut13.h"
#include "nutcpp/encoding/convert_utils.h"

// Internal BIP-39 for seed derivation in tests
#include "../src/nuts/bip39.h"

using namespace nutcpp;

// ====================================================================
// Common test data (from DotNut UnitTest1.cs lines 588-645)
// ====================================================================

static const std::string MNEMONIC = "half depart obvious quality work element tank gorilla view sugar picture humble";

static std::vector<uint8_t> get_seed() {
    return internal::mnemonic_to_seed(MNEMONIC);
}

// ====================================================================
// get_keyset_id_int
// ====================================================================

TEST_CASE("NUT-13 get_keyset_id_int v0 keyset", "[nut13]") {
    KeysetId kid("009a1f293253e41e");
    REQUIRE(get_keyset_id_int(kid) == 864559728);
}

TEST_CASE("NUT-13 get_keyset_id_int v1 keyset truncates to 8 bytes", "[nut13]") {
    // v1 keyset IDs are longer; first 16 hex chars are used
    KeysetId kid("015ba18a8adcd02e715a58358eb618da4a4b3791151a4bee5e968bb88406ccf76a");
    uint32_t val = get_keyset_id_int(kid);
    // Verify it's a valid result (truncated to 8 bytes, mod 2^31-1)
    REQUIRE(val > 0);
    REQUIRE(val < 0x7FFFFFFFUL);
}

// ====================================================================
// get_derivation_path
// ====================================================================

TEST_CASE("NUT-13 derivation path secret", "[nut13]") {
    KeysetId kid("009a1f293253e41e");
    REQUIRE(get_derivation_path(kid, 0, true) == "m/129372'/0'/864559728'/0'/0");
}

TEST_CASE("NUT-13 derivation path blinding factor", "[nut13]") {
    KeysetId kid("009a1f293253e41e");
    REQUIRE(get_derivation_path(kid, 0, false) == "m/129372'/0'/864559728'/0'/1");
}

// ====================================================================
// NUT-13 v0 (BIP-32): DotNut Nut13Tests (lines 588-623)
// keyset_id = "009a1f293253e41e"
// ====================================================================

TEST_CASE("NUT-13 v0 derive_secret counters 0-4", "[nut13]") {
    auto seed = get_seed();
    KeysetId kid("009a1f293253e41e");

    REQUIRE(derive_secret(seed, kid, 0) == "485875df74771877439ac06339e284c3acfcd9be7abf3bc20b516faeadfe77ae");
    REQUIRE(derive_secret(seed, kid, 1) == "8f2b39e8e594a4056eb1e6dbb4b0c38ef13b1b2c751f64f810ec04ee35b77270");
    REQUIRE(derive_secret(seed, kid, 2) == "bc628c79accd2364fd31511216a0fab62afd4a18ff77a20deded7b858c9860c8");
    REQUIRE(derive_secret(seed, kid, 3) == "59284fd1650ea9fa17db2b3acf59ecd0f2d52ec3261dd4152785813ff27a33bf");
    REQUIRE(derive_secret(seed, kid, 4) == "576c23393a8b31cc8da6688d9c9a96394ec74b40fdaf1f693a6bb84284334ea0");
}

TEST_CASE("NUT-13 v0 derive_blinding_factor counters 0-4", "[nut13]") {
    auto seed = get_seed();
    KeysetId kid("009a1f293253e41e");

    auto to_hex = [](const std::vector<uint8_t>& v) {
        return bytes_to_hex(v.data(), v.size());
    };

    REQUIRE(to_hex(derive_blinding_factor(seed, kid, 0)) == "ad00d431add9c673e843d4c2bf9a778a5f402b985b8da2d5550bf39cda41d679");
    REQUIRE(to_hex(derive_blinding_factor(seed, kid, 1)) == "967d5232515e10b81ff226ecf5a9e2e2aff92d66ebc3edf0987eb56357fd6248");
    REQUIRE(to_hex(derive_blinding_factor(seed, kid, 2)) == "b20f47bb6ae083659f3aa986bfa0435c55c6d93f687d51a01f26862d9b9a4899");
    REQUIRE(to_hex(derive_blinding_factor(seed, kid, 3)) == "fb5fca398eb0b1deb955a2988b5ac77d32956155f1c002a373535211a2dfdc29");
    REQUIRE(to_hex(derive_blinding_factor(seed, kid, 4)) == "5f09bfbfe27c439a597719321e061e2e40aad4a36768bb2bcc3de547c9644bf9");
}

// ====================================================================
// NUT-13 v1 (HMAC-SHA256): DotNut Nut13HMACTests (lines 626-645)
// keyset_id = "015ba18a8adcd02e715a58358eb618da4a4b3791151a4bee5e968bb88406ccf76a"
// ====================================================================

TEST_CASE("NUT-13 v1 derive_secret counters 0-4", "[nut13]") {
    auto seed = get_seed();
    KeysetId kid("015ba18a8adcd02e715a58358eb618da4a4b3791151a4bee5e968bb88406ccf76a");

    REQUIRE(derive_secret(seed, kid, 0) == "db5561a07a6e6490f8dadeef5be4e92f7cebaecf2f245356b5b2a4ec40687298");
    REQUIRE(derive_secret(seed, kid, 1) == "b70e7b10683da3bf1cdf0411206f8180c463faa16014663f39f2529b2fda922e");
    REQUIRE(derive_secret(seed, kid, 2) == "78a7ac32ccecc6b83311c6081b89d84bb4128f5a0d0c5e1af081f301c7a513f5");
    REQUIRE(derive_secret(seed, kid, 3) == "094a2b6c63bfa7970bc09cda0e1cfc9cd3d7c619b8e98fabcfc60aea9e4963e5");
    REQUIRE(derive_secret(seed, kid, 4) == "5e89fc5d30d0bf307ddf0a3ac34aa7a8ee3702169dafa3d3fe1d0cae70ecd5ef");
}

TEST_CASE("NUT-13 v1 derive_blinding_factor counters 0-4", "[nut13]") {
    auto seed = get_seed();
    KeysetId kid("015ba18a8adcd02e715a58358eb618da4a4b3791151a4bee5e968bb88406ccf76a");

    auto to_hex = [](const std::vector<uint8_t>& v) {
        return bytes_to_hex(v.data(), v.size());
    };

    REQUIRE(to_hex(derive_blinding_factor(seed, kid, 0)) == "6d26181a3695e32e9f88b80f039ba1ae2ab5a200ad4ce9dbc72c6d3769f2b035");
    REQUIRE(to_hex(derive_blinding_factor(seed, kid, 1)) == "bde4354cee75545bea1a2eee035a34f2d524cee2bb01613823636e998386952e");
    REQUIRE(to_hex(derive_blinding_factor(seed, kid, 2)) == "f40cc1218f085b395c8e1e5aaa25dccc851be3c6c7526a0f4e57108f12d6dac4");
    REQUIRE(to_hex(derive_blinding_factor(seed, kid, 3)) == "099ed70fc2f7ac769bc20b2a75cb662e80779827b7cc358981318643030577d0");
    REQUIRE(to_hex(derive_blinding_factor(seed, kid, 4)) == "5550337312d223ba62e3f75cfe2ab70477b046d98e3e71804eade3956c7b98cf");
}

// ====================================================================
// Edge cases
// ====================================================================

TEST_CASE("NUT-13 unsupported keyset version throws", "[nut13]") {
    auto seed = get_seed();
    KeysetId kid("029a1f293253e41e"); // version 0x02 — unsupported

    REQUIRE_THROWS_AS(derive_secret(seed, kid, 0), std::invalid_argument);
    REQUIRE_THROWS_AS(derive_blinding_factor(seed, kid, 0), std::invalid_argument);
}
