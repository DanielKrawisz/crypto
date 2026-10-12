// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include <crypto/ElGamel.hpp>
#include <data/math/number/eratosthenes.hpp>
#include <data/math/number/primitive_root.hpp>
#include <data/math/number/NTL/random.hpp>

namespace crypto {

    template <typename EG> struct test_ElGamel {
        void encryption (random::source &oo, const EG::element &m1, const EG::element &m2) {
            EXPECT_NE (m1, m2);

            // generate keys
            typename EG::secret secret1 = EG::generate_key (oo);
            typename EG::secret secret2;
            do {
                oo >> secret2;
            } while (secret1 == secret2);

            EXPECT_TRUE (secret1.valid ());
            EXPECT_TRUE (secret2.valid ());

            EXPECT_NE (secret1, secret2);

            // generate public key
            auto pubkey1 = secret1.to_public ();
            auto pubkey2 = secret2.to_public ();

            EXPECT_NE (pubkey1, pubkey2);

            auto encrypted11 = pubkey1.encrypt (m1, oo);
            auto encrypted12 = pubkey1.encrypt (m2, oo);
            auto encrypted21 = pubkey2.encrypt (m1, oo);
            auto encrypted22 = pubkey2.encrypt (m2, oo);

            EXPECT_NE (encrypted11, encrypted12);
            EXPECT_NE (encrypted11, encrypted21);
            EXPECT_NE (encrypted11, encrypted22);

            auto decrypted111 = secret1.decrypt (encrypted11);
            auto decrypted112 = secret1.decrypt (encrypted12);

            EXPECT_EQ (m1, decrypted111);
            EXPECT_EQ (m2, decrypted112);

            auto decrypted121 = secret1.decrypt (encrypted21);
            auto decrypted122 = secret1.decrypt (encrypted22);

            EXPECT_NE (m1, decrypted121);
            EXPECT_NE (m2, decrypted122);

            auto decrypted211 = secret2.decrypt (encrypted11);
            auto decrypted212 = secret2.decrypt (encrypted12);

            EXPECT_NE (m1, decrypted211);
            EXPECT_NE (m2, decrypted212);

            auto decrypted221 = secret2.decrypt (encrypted21);
            auto decrypted222 = secret2.decrypt (encrypted22);

            EXPECT_EQ (m1, decrypted221);
            EXPECT_EQ (m2, decrypted222);
        }

        void signature (random::source &oo, const EG::digest &h1, const EG::digest &h2) {
            EXPECT_NE (h1, h2);

            // generate keys
            typename EG::secret secret1 = EG::generate_key (oo);
            typename EG::secret secret2;
            do {
                oo >> secret2;
            } while (secret1 == secret2);

            EXPECT_TRUE (secret1.valid ());
            EXPECT_TRUE (secret2.valid ());

            EXPECT_NE (secret1, secret2);

            // generate public key
            auto pubkey1 = secret1.to_public ();
            auto pubkey2 = secret2.to_public ();

            EXPECT_NE (pubkey1, pubkey2);

            auto signed11 = secret1.sign (h1, oo);
            auto signed12 = secret1.sign (h2, oo);
            auto signed21 = secret2.sign (h1, oo);
            auto signed22 = secret2.sign (h2, oo);

            EXPECT_NE (signed11, signed12);
            EXPECT_NE (signed11, signed21);
            EXPECT_NE (signed11, signed22);

            EXPECT_TRUE (pubkey1.verify (signed11, h1));
            EXPECT_TRUE (pubkey1.verify (signed12, h2));
            EXPECT_TRUE (pubkey2.verify (signed21, h1));
            EXPECT_TRUE (pubkey2.verify (signed22, h2));

            EXPECT_FALSE (pubkey1.verify (signed11, h2));
            EXPECT_FALSE (pubkey1.verify (signed12, h1));
            EXPECT_FALSE (pubkey2.verify (signed21, h2));
            EXPECT_FALSE (pubkey2.verify (signed22, h1));

            EXPECT_FALSE (pubkey2.verify (signed11, h1));
            EXPECT_FALSE (pubkey2.verify (signed12, h2));
            EXPECT_FALSE (pubkey1.verify (signed21, h1));
            EXPECT_FALSE (pubkey1.verify (signed22, h2));
        }

    };

    template <typename X> struct ElGamelTest;

    template <auto gen, auto order>
    struct ElGamelTest<ElGamel<gen, order>> : ::testing::Test {
        using group = ElGamel<gen, order>;
        constexpr static const auto Generator = gen;
        constexpr static const auto Order = order;
    };

    // some toy cryptosystems for El Gamel
    // TODO these all ought to work in uint32 but they don't. '
    using El_Gamel_params = ::testing::Types<
        ElGamel<math::prime_field<uint64 {271}> {uint64 {6}},  uint64 {270}>,
        ElGamel<math::prime_field<uint64 {293}> {uint64 {2}},  uint64 {292}>,
        ElGamel<math::prime_field<uint64 {307}> {uint64 {5}},  uint64 {306}>,
        ElGamel<math::prime_field<uint64 {317}> {uint64 {2}},  uint64 {316}>,
        ElGamel<math::prime_field<uint64 {353}> {uint64 {3}},  uint64 {352}>,
        ElGamel<math::prime_field<uint64 {359}> {uint64 {7}},  uint64 {358}>,
        ElGamel<math::prime_field<uint64 {367}> {uint64 {6}},  uint64 {366}>,
        ElGamel<math::prime_field<uint64 {373}> {uint64 {2}},  uint64 {372}>,
        ElGamel<math::prime_field<uint64 {383}> {uint64 {5}},  uint64 {382}>,
        ElGamel<math::prime_field<uint64 {401}> {uint64 {3}},  uint64 {400}>,
        ElGamel<math::prime_field<uint64 {419}> {uint64 {2}},  uint64 {418}>,
        ElGamel<math::prime_field<uint64 {433}> {uint64 {5}},  uint64 {432}>,
        ElGamel<math::prime_field<uint64 {439}> {uint64 {15}}, uint64 {438}>,
        ElGamel<math::prime_field<uint64 {443}> {uint64 {2}},  uint64 {442}>,
        ElGamel<math::prime_field<uint64 {449}> {uint64 {3}},  uint64 {448}>,
        ElGamel<math::prime_field<uint64 {457}> {uint64 {13}}, uint64 {456}>,
        ElGamel<math::prime_field<uint64 {461}> {uint64 {2}},  uint64 {460}>,
        ElGamel<math::prime_field<uint64 {463}> {uint64 {3}},  uint64 {462}>,
        ElGamel<math::prime_field<uint64 {467}> {uint64 {2}},  uint64 {466}>,
        ElGamel<math::prime_field<uint64 {479}> {uint64 {13}}, uint64 {478}>,
        ElGamel<math::prime_field<uint64 {487}> {uint64 {3}},  uint64 {486}>,
        ElGamel<math::prime_field<uint64 {499}> {uint64 {7}},  uint64 {498}>,
        ElGamel<math::prime_field<uint64 {503}> {uint64 {5}},  uint64 {502}>,
        ElGamel<math::prime_field<uint64 {509}> {uint64 {2}},  uint64 {508}>,
        ElGamel<math::prime_field<uint64 {739}> {uint64 {3}},  uint64 {738}>,
        ElGamel<math::prime_field<uint64 {1117}> {uint64 {2}},  uint64 {1116}>,
        ElGamel<math::prime_field<uint64 {3691}> {uint64 {2}},  uint64 {3690}>,
        ElGamel<math::prime_field<uint64 {8147}> {uint64 {2}},  uint64 {8146}>,
        ElGamel<math::prime_field<uint64 {12301}> {uint64 {2}},  uint64 {12300}>,
        ElGamel<math::prime_field<uint64 {22721}> {uint64 {3}},  uint64 {22720}>,
        ElGamel<math::prime_field<uint64 {64091}> {uint64 {2}},  uint64 {64090}>,
        ElGamel<math::prime_field<uint64 {68281}> {uint64 {7}},  uint64 {68280}>,
        ElGamel<math::prime_field<uint64 {143791}> {uint64 {6}},  uint64 {143790}>,
        ElGamel<math::prime_field<uint64 {397973}> {uint64 {2}},  uint64 {397972}>,
        ElGamel<math::prime_field<uint64 {941791}> {uint64 {6}},  uint64 {941790}>,
        ElGamel<math::prime_field<uint64 {1981753}> {uint64 {10}},  uint64 {1981752}>,
        ElGamel<math::prime_field<uint64 {2117513}> {uint64 {3}},  uint64 {2117512}>,
        ElGamel<math::prime_field<uint64 {5846957}> {uint64 {2}},  uint64 {5846956}>,
        ElGamel<math::prime_field<uint64 {13492253}> {uint64 {2}},  uint64 {13492252}>,
        ElGamel<math::prime_field<uint64 {31976671}> {uint64 {11}},  uint64 {31976670}>,
        ElGamel<math::prime_field<uint64 {49911149}> {uint64 {2}},  uint64 {49911148}>,
        ElGamel<math::prime_field<uint64 {98046119}> {uint64 {13}},  uint64 {98046118}>,
        ElGamel<math::prime_field<uint64 {114762779}> {uint64 {2}},  uint64 {114762778}>
    >;

    TYPED_TEST_SUITE (ElGamelTest, El_Gamel_params);

    random::std_random<std::default_random_engine> r_eg {78739227};

    TYPED_TEST (ElGamelTest, ElGamel) {
        using G = typename TestFixture::group;
        constexpr static const auto Generator = TestFixture::Generator;
        constexpr static const auto Order = TestFixture::Order;

        test_ElGamel<G> {}.encryption (r_eg, uint64 {25}, uint64 {83});
        test_ElGamel<G> {}.signature (r_eg, uint64 {77}, uint64 {124});
    }

}

