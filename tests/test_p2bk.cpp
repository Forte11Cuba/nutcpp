#include <catch2/catch_test_macros.hpp>
#include "nutcpp/nuts/p2bk.h"
#include "nutcpp/nuts/p2pk.h"
#include "nutcpp/encoding/convert_utils.h"

using namespace nutcpp;
using namespace std;

// ============================================================
// NUT-28 test vectors from specs/tests/28-tests.md
// ============================================================

static const char* E_HEX = "1cedb9df0c6872188b560ace9e35fd55c2532d53e19ae65b46159073886482ca";
static const char* E_PUB  = "02a8cda4cf448bfce9a9e46e588c06ea1780fcb94e3bbdf3277f42995d403a8b0c";
static const char* P_HEX = "ad37e8abd800be3e8272b14045873f4353327eedeb702b72ddcc5c5adff5129c";
static const char* P_PUB  = "02771fed6cb88aaac38b8b32104a942bf4b8f4696bc361171b3c7d06fa2ebddf06";
static const char* ZX_HEX = "40d6ba4430a6dfa915bb441579b0f4dee032307434e9957a092bbca73151df8b";

static const char* RI_HEX[11] = {
    "f43cfecf4d44e109872ed601156a01211c0d9eba0460d5be254a510782a2d4aa",
    "4a57e6acb9db19344af5632aa45000cd2c643550bc63c7d5732221171ab0f5b3",
    "d4a8b84b21f2b0ad31654e96eddbc32bfdedae2d05dc179bdd6cc20236b1104d",
    "ecebf43123d1da3de611a05f5020085d63ca20829242cdc07f7c780e19594798",
    "5f42d463ead44cbb20e51843d9eb3b8b0e0021566fd89852d23ae85f57d60858",
    "a8f1c9d336954997ad571e5a5b59fe340c80902b10b9099d44e17abb3070118c",
    "c39fa43b707215c163593fb8cadc0eddb4fe2f82c0c79c82a6fc2e3b6b051a7e",
    "b17d6a51396eb926f4a901e20ff760a852563f90fd4b85e193888f34fd2ee523",
    "4d4af85ea296457155b7ce328cf9accbe232e8ac23a1dfe901a36ab1b72ea04d",
    "ce311248ea9f42a73fc874b3ce351d55964652840d695382f0018b36bb089dd1",
    "9de35112d62e6343d02301d8f58fef87958e99bb68cfdfa855e04fe18b95b114",
};

static const char* BLINDED_PK[11] = {
    "03b7c03eb05a0a539cfc438e81bcf38b65b7bb8685e8790f9b853bfe3d77ad5315",
    "0352fb6d93360b7c2538eedf3c861f32ea5883fceec9f3e573d9d84377420da838",
    "03667361ca925065dcafea0a705ba49e75bdd7975751fcc933e05953463c79fff1",
    "02aca3ed09382151250b38c85087ae0a1436a057b40f824a5569ba353d40347d08",
    "02cd397bd6e326677128f1b0e5f1d745ad89b933b1b8671e947592778c9fc2301d",
    "0394140369aae01dbaf74977ccbb09b3a9cf2252c274c791ac734a331716f1f7d4",
    "03480f28e8f8775d56a4254c7e0dfdd5a6ecd6318c757fcec9e84c1b48ada0666d",
    "02f8a7be813f7ba2253d09705cc68c703a9fd785a055bf8766057fc6695ec80efc",
    "03aa5446aaf07ca9730b233f5c404fd024ef92e3787cd1c34c81c0778fe23c59e9",
    "037f82d4e0a79b0624a58ef7181344b95afad8acf4275dad49bcd39c189b73ece2",
    "032371fc0eef6885062581a3852494e2eab8f384b7dd196281b85b77f94770fac5",
};

static const char* SK_STD[11] = {
    "a174e77b25459f4809a187415af14065b49140c1408860f543444ed59261a605",
    "f78fcf5891dbd772cd68146ae9d740107f96b43ea7d3f34850ee7d71faa6084f",
    "81e0a0f6f9f36eebb3d7ffd733630270967150344203a2d2fb66bfd0466fe1a8",
    "9a23dcdcfbd2987c6884519f95a747a1fc4dc289ce6a58f79d7675dc291818f3",
    "0c7abd0fc2d50af9a357c9841f727acfa683c35dac002389f034e62d6794d9b3",
    "5629b27f0e9607d62fc9cf9aa0e13d78a50432324ce094d462db7889402ee2e7",
    "70d78ce74872d3ffe5cbf0f910634e224d81d189fcef27b9c4f62c097ac3ebd9",
    "5eb552fd116f7765771bb322557e9fecead9e19839731118b1828d030cedb67e",
    "fa82e10a7a9703afd82a7f72d280ec0f3565679a0f120b5bdf6fc70c9723b2e9",
    "7b68faf4c2a000e5c23b25f413bc5c9a2ec9f48b4990deba0dfb8904cac76f2c",
    "4b1b39beae2f21825295b3193b172ecc2e123bc2a4f76adf73da4daf9b54826f",
};

static const char* SK_NEG[11] = {
    "47051623754422cb04bc24c0cfe2c1ddc8db1fcc18f0aa4b477df4aca2adc20e",
    "9d1ffe00e1da5af5c882b1ea5ec8c18893e09349803c3c9e552823490af22458",
    "2770cf9f49f1f26eaef29d56a85483e8aabb2f3f1a6bec28ffa065a756bbfdb1",
    "3fb40b854bd11bff639eef1f0a98c91a1097a194a6d2a24da1b01bb3396434fc",
    "b20aebb812d38e7c9e7267039463fc46757c7f4f33b10d1bb440ea91481736fd",
    "fbb9e1275e948b592ae46d1a15d2beef73fcee23d4917e6626e77ced20b14031",
    "1667bb8f98715782e0e68e788554cf9a61cbb094d557710fc92fd1e08b1007e2",
    "044581a5616dfae8723650a1ca702164ff23c0a311db5a6eb5bc32da1d39d287",
    "a0130fb2ca958732d3451cf247726d8749af46a4e77a54b1e3a96ce3a76fcef2",
    "20f9299d129e8468bd55c37388adde124313d39621f9281012352edbdb138b35",
    "f0ab6866fe2da5054db05098b008b042fd0af7b42ca8547137e652137bd6dfb9",
};

TEST_CASE("NUT-28 P2BK", "[p2bk][nut28]") {

    SECTION("keypair derivation") {
        PrivKey e(E_HEX);
        CHECK(e.get_pub_key().to_hex() == E_PUB);

        PrivKey p(P_HEX);
        // Natural pubkey pG has prefix 03 (odd Y), but test vector P has 02 (even Y).
        // This parity mismatch is expected — it's why P2BK tries both standard
        // and negated derivations. Same x-coordinate, different Y parity.
        string pG = p.get_pub_key().to_hex();
        CHECK(pG == "03771fed6cb88aaac38b8b32104a942bf4b8f4696bc361171b3c7d06fa2ebddf06");
        CHECK(pG.substr(2) == string(P_PUB).substr(2));  // same x-coord
    }

    SECTION("compute_zx symmetry: e*P == p*E") {
        PrivKey e(E_HEX);
        PubKey P(P_PUB);
        PrivKey p(P_HEX);
        PubKey E(E_PUB);

        auto zx1 = compute_zx(e, P);
        auto zx2 = compute_zx(p, E);

        CHECK(bytes_to_hex(zx1) == ZX_HEX);
        CHECK(bytes_to_hex(zx2) == ZX_HEX);
    }

    SECTION("compute_ri: all 11 blinding scalars") {
        auto Zx = hex_to_bytes(ZX_HEX);
        for (int i = 0; i < 11; ++i) {
            auto ri = compute_ri(Zx, i);
            CHECK(ri.to_hex() == RI_HEX[i]);
        }
    }

    SECTION("compute_blinded_key: all 11 blinded pubkeys") {
        auto Zx = hex_to_bytes(ZX_HEX);
        PubKey P(P_PUB);
        for (int i = 0; i < 11; ++i) {
            auto ri = compute_ri(Zx, i);
            auto blinded = compute_blinded_key(P, ri);
            CHECK(blinded.to_hex() == BLINDED_PK[i]);
        }
    }

    SECTION("derived secret keys: standard (p + ri)") {
        PrivKey p(P_HEX);
        auto Zx = hex_to_bytes(ZX_HEX);

        for (int i = 0; i < 11; ++i) {
            auto ri = compute_ri(Zx, i);

            // Manually compute p + ri
            unsigned char sk[32];
            memcpy(sk, p.data(), 32);
            auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
            REQUIRE(secp256k1_ec_seckey_tweak_add(ctx, sk, ri.data()));
            secp256k1_context_destroy(ctx);

            CHECK(bytes_to_hex(sk, 32) == SK_STD[i]);
        }
    }

    SECTION("derived secret keys: negated (-p + ri)") {
        PrivKey p(P_HEX);
        auto Zx = hex_to_bytes(ZX_HEX);

        for (int i = 0; i < 11; ++i) {
            auto ri = compute_ri(Zx, i);

            // Manually compute -p + ri
            unsigned char sk[32];
            memcpy(sk, p.data(), 32);
            auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
            REQUIRE(secp256k1_ec_seckey_negate(ctx, sk));
            REQUIRE(secp256k1_ec_seckey_tweak_add(ctx, sk, ri.data()));
            secp256k1_context_destroy(ctx);

            CHECK(bytes_to_hex(sk, 32) == SK_NEG[i]);
        }
    }

    SECTION("build_blinded with known E") {
        PrivKey e(E_HEX);
        PrivKey p1("ad37e8abd800be3e8272b14045873f4353327eedeb702b72ddcc5c5adff5129c");
        PrivKey p2("1cedb9df0c6872188b560ace9e35fd55c2532d53e19ae65b46159073886482ca");
        PubKey P1 = p1.get_pub_key();
        PubKey P2 = p2.get_pub_key();

        P2PKBuilder builder;
        builder.pubkeys = {P1, P2};
        builder.signature_threshold = 2;
        builder.sig_flag = "SIG_INPUTS";
        builder.lock = 21000000000LL;
        builder.refund_pubkeys = {P1};

        // Remember original pubkeys for verification
        string P1_hex = P1.to_hex();
        string P2_hex = P2.to_hex();

        auto ps = build_blinded(builder, e);

        // data should be blinded P1 (slot 0)
        CHECK(ps.data != P1_hex);

        // Verify blinded keys match expected values
        auto Zx1 = compute_zx(e, P1);
        auto r0 = compute_ri(Zx1, 0);
        auto expected_data = compute_blinded_key(P1, r0);
        CHECK(ps.data == expected_data.to_hex());

        // pubkeys tag should have blinded P2 (slot 1)
        auto* pktag = ps.find_tag("pubkeys");
        REQUIRE(pktag);
        REQUIRE(pktag->size() >= 2);
        auto Zx2 = compute_zx(e, P2);
        auto r1 = compute_ri(Zx2, 1);
        auto expected_pk2 = compute_blinded_key(P2, r1);
        CHECK((*pktag)[1] == expected_pk2.to_hex());

        // refund tag should have blinded P1 (slot 2, global index)
        auto* rtag = ps.find_tag("refund");
        REQUIRE(rtag);
        REQUIRE(rtag->size() >= 2);
        auto r2 = compute_ri(Zx1, 2);  // global slot index = 2
        auto expected_refund = compute_blinded_key(P1, r2);
        CHECK((*rtag)[1] == expected_refund.to_hex());
    }

    SECTION("full flow: build_blinded + generate_blind_witness + verify") {
        PrivKey e(E_HEX);
        PrivKey p("ad37e8abd800be3e8272b14045873f4353327eedeb702b72ddcc5c5adff5129c");
        PubKey P = p.get_pub_key();
        PubKey E(E_PUB);

        P2PKBuilder builder;
        builder.pubkeys = {P};
        builder.signature_threshold = 1;

        auto ps = build_blinded(builder, e);

        // Message to sign (simulating proof secret bytes)
        string msg_str = "test message for p2bk";
        vector<unsigned char> msg(msg_str.begin(), msg_str.end());

        // Generate blind witness
        auto witness = generate_blind_witness(ps, msg, {p}, E);
        REQUIRE(witness.has_value());
        CHECK(witness->signatures.size() == 1);

        // Verify: the blinded pubkey in ps.data should verify the signature
        CHECK(ps.verify_witness(msg, *witness));
    }

    SECTION("full flow with 2-of-2 multisig + refund") {
        PrivKey e(E_HEX);
        PrivKey p1("ad37e8abd800be3e8272b14045873f4353327eedeb702b72ddcc5c5adff5129c");
        PrivKey p2("1cedb9df0c6872188b560ace9e35fd55c2532d53e19ae65b46159073886482ca");
        PubKey P1 = p1.get_pub_key();
        PubKey P2 = p2.get_pub_key();

        P2PKBuilder builder;
        builder.pubkeys = {P1, P2};
        builder.signature_threshold = 2;
        builder.sig_flag = "SIG_INPUTS";
        builder.lock = 21000000000LL;
        builder.refund_pubkeys = {P1};

        auto ps = build_blinded(builder, e);
        PubKey E(E_PUB);

        string msg_str = "test multisig p2bk";
        vector<unsigned char> msg(msg_str.begin(), msg_str.end());

        // Generate blind witness with both keys
        auto witness = generate_blind_witness(ps, msg, {p1, p2}, E);
        REQUIRE(witness.has_value());
        CHECK(witness->signatures.size() == 2);

        // Verify
        CHECK(ps.verify_witness(msg, *witness));
    }

    SECTION("full flow with random E") {
        PrivKey p("ad37e8abd800be3e8272b14045873f4353327eedeb702b72ddcc5c5adff5129c");
        PubKey P = p.get_pub_key();

        P2PKBuilder builder;
        builder.pubkeys = {P};
        builder.signature_threshold = 1;

        auto [ps, E] = build_blinded(builder);

        string msg_str = "random E test";
        vector<unsigned char> msg(msg_str.begin(), msg_str.end());

        auto witness = generate_blind_witness(ps, msg, {p}, E);
        REQUIRE(witness.has_value());
        CHECK(witness->signatures.size() == 1);

        CHECK(ps.verify_witness(msg, *witness));
    }

    SECTION("wrong key fails to sign") {
        PrivKey e(E_HEX);
        PrivKey p("ad37e8abd800be3e8272b14045873f4353327eedeb702b72ddcc5c5adff5129c");
        PubKey P = p.get_pub_key();

        P2PKBuilder builder;
        builder.pubkeys = {P};
        builder.signature_threshold = 1;

        auto ps = build_blinded(builder, e);
        PubKey E(E_PUB);

        string msg_str = "wrong key test";
        vector<unsigned char> msg(msg_str.begin(), msg_str.end());

        // Use a different key that wasn't used in blinding
        PrivKey wrong_key("1cedb9df0c6872188b560ace9e35fd55c2532d53e19ae65b46159073886482ca");
        CHECK_THROWS(generate_blind_witness(ps, msg, {wrong_key}, E));
    }
}
