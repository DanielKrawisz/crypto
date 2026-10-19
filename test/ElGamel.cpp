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
        ElGamel<math::prime_field<uint32 {271}>       {uint32 {6}},  uint32 {270}>,
        ElGamel<math::prime_field<uint32 {293}>       {uint32 {2}},  uint32 {292}>,
        ElGamel<math::prime_field<uint32 {307}>       {uint32 {5}},  uint32 {306}>,
        ElGamel<math::prime_field<uint32 {317}>       {uint32 {2}},  uint32 {316}>,
        ElGamel<math::prime_field<uint32 {353}>       {uint32 {3}},  uint32 {352}>,
        ElGamel<math::prime_field<uint32 {359}>       {uint32 {7}},  uint32 {358}>,
        ElGamel<math::prime_field<uint32 {367}>       {uint32 {6}},  uint32 {366}>,
        ElGamel<math::prime_field<uint32 {373}>       {uint32 {2}},  uint32 {372}>,
        ElGamel<math::prime_field<uint32 {383}>       {uint32 {5}},  uint32 {382}>,
        ElGamel<math::prime_field<uint32 {401}>       {uint32 {3}},  uint32 {400}>,
        ElGamel<math::prime_field<uint32 {419}>       {uint32 {2}},  uint32 {418}>,
        ElGamel<math::prime_field<uint32 {433}>       {uint32 {5}},  uint32 {432}>,
        ElGamel<math::prime_field<uint32 {439}>       {uint32 {15}}, uint32 {438}>,
        ElGamel<math::prime_field<uint32 {443}>       {uint32 {2}},  uint32 {442}>,
        ElGamel<math::prime_field<uint32 {449}>       {uint32 {3}},  uint32 {448}>,
        ElGamel<math::prime_field<uint32 {457}>       {uint32 {13}}, uint32 {456}>,
        ElGamel<math::prime_field<uint32 {461}>       {uint32 {2}},  uint32 {460}>,
        ElGamel<math::prime_field<uint32 {463}>       {uint32 {3}},  uint32 {462}>,
        ElGamel<math::prime_field<uint32 {467}>       {uint32 {2}},  uint32 {466}>,
        ElGamel<math::prime_field<uint32 {479}>       {uint32 {13}}, uint32 {478}>,
        ElGamel<math::prime_field<uint32 {487}>       {uint32 {3}},  uint32 {486}>,
        ElGamel<math::prime_field<uint32 {499}>       {uint32 {7}},  uint32 {498}>,
        ElGamel<math::prime_field<uint32 {503}>       {uint32 {5}},  uint32 {502}>,
        ElGamel<math::prime_field<uint32 {509}>       {uint32 {2}},  uint32 {508}>,
        ElGamel<math::prime_field<uint32 {739}>       {uint32 {3}},  uint32 {738}>,
        ElGamel<math::prime_field<uint32 {1117}>      {uint32 {2}},  uint32 {1116}>,
        ElGamel<math::prime_field<uint32 {3691}>      {uint32 {2}},  uint32 {3690}>,
        ElGamel<math::prime_field<uint32 {8147}>      {uint32 {2}},  uint32 {8146}>,
        ElGamel<math::prime_field<uint32 {12301}>     {uint32 {2}},  uint32 {12300}>,
        ElGamel<math::prime_field<uint32 {22721}>     {uint32 {3}},  uint32 {22720}>,
        ElGamel<math::prime_field<uint32 {64091}>     {uint32 {2}},  uint32 {64090}>,
        ElGamel<math::prime_field<uint32 {68281}>     {uint32 {7}},  uint32 {68280}>,
        ElGamel<math::prime_field<uint32 {143791}>    {uint32 {6}},  uint32 {143790}>,
        ElGamel<math::prime_field<uint32 {397973}>    {uint32 {2}},  uint32 {397972}>,
        ElGamel<math::prime_field<uint32 {941791}>    {uint32 {6}},  uint32 {941790}>,
        ElGamel<math::prime_field<uint32 {1981753}>   {uint32 {10}}, uint32 {1981752}>,
        ElGamel<math::prime_field<uint32 {2117513}>   {uint32 {3}},  uint32 {2117512}>,
        ElGamel<math::prime_field<uint32 {5846957}>   {uint32 {2}},  uint32 {5846956}>,
        ElGamel<math::prime_field<uint32 {13492253}>  {uint32 {2}},  uint32 {13492252}>,
        ElGamel<math::prime_field<uint32 {31976671}>  {uint32 {11}}, uint32 {31976670}>,
        ElGamel<math::prime_field<uint32 {49911149}>  {uint32 {2}},  uint32 {49911148}>,
        ElGamel<math::prime_field<uint32 {98046119}>  {uint32 {13}}, uint32 {98046118}>,
        ElGamel<math::prime_field<uint32 {114762779}> {uint32 {2}},  uint32 {114762778}>
    >;

    TYPED_TEST_SUITE (ElGamelTest, El_Gamel_params);

    random::std_random<std::default_random_engine> r_eg {78739227};

    TYPED_TEST (ElGamelTest, ElGamel) {
        using G = typename TestFixture::group;
        constexpr static const auto Generator = TestFixture::Generator;
        constexpr static const auto Order = TestFixture::Order;

        test_ElGamel<G> {}.encryption (r_eg, uint32 {25}, uint32 {83});
        test_ElGamel<G> {}.signature (r_eg, uint32 {77}, uint32 {124});
    }

}

