// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include <crypto/Rabin.hpp>
#include <data/math/number/eratosthenes.hpp>
#include <data/math/number/primitive_root.hpp>
#include <data/math/number/NTL/random.hpp>
#include <data/math/number/random.hpp>

namespace crypto {

    template <typename Rabin, typename N> void test_Rabin (random::source &oo) {

        // generate keys
        typename Rabin::secret secret1 = Rabin::generate_key (oo);
        typename Rabin::secret secret2;
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

        auto max_message = min (pubkey1.N.Value, pubkey2.N.Value);

        N m1 = math::number::generate_random_below<N> (oo, max_message);
        N m2 = math::number::generate_random_below<N> (oo, max_message);

        ASSERT_NE (m1, m2);

        auto encrypted11 = pubkey1.encrypt (m1);
        auto encrypted12 = pubkey1.encrypt (m2);
        auto encrypted21 = pubkey2.encrypt (m1);
        auto encrypted22 = pubkey2.encrypt (m2);

        EXPECT_NE (encrypted11, encrypted12);
        EXPECT_NE (encrypted11, encrypted21);
        EXPECT_NE (encrypted11, encrypted22);

        auto decrypted121 = secret1.decrypt (encrypted21);
        auto decrypted122 = secret1.decrypt (encrypted22);

        EXPECT_FALSE ((contains (decrypted121, m1)));
        EXPECT_FALSE ((contains (decrypted122, m2)));

        auto decrypted211 = secret2.decrypt (encrypted11);
        auto decrypted212 = secret2.decrypt (encrypted12);

        EXPECT_FALSE ((contains (decrypted211, m1)));
        EXPECT_FALSE ((contains (decrypted212, m2)));

        auto decrypted111 = secret1.decrypt (encrypted11);
        auto decrypted112 = secret1.decrypt (encrypted12);

        auto decrypted221 = secret2.decrypt (encrypted21);
        auto decrypted222 = secret2.decrypt (encrypted22);

        EXPECT_EQ (decrypted111.size (), 4);
        EXPECT_EQ (decrypted112.size (), 4);
        EXPECT_EQ (decrypted221.size (), 4);
        EXPECT_EQ (decrypted222.size (), 4);

        auto n1 = math::nonzero {secret1.P.Value * secret1.Q.Value};
        auto n2 = math::nonzero {secret2.Q.Value * secret2.P.Value};

        for (const auto &m : decrypted111) {
            auto sqm = square_mod (m, n1);
            EXPECT_EQ ((sqm), encrypted11) << "decrypted message " << m << " squared -> " << sqm << " != " << m1 << " mod " << n1;
        }

        for (const auto &m : decrypted112) {
            auto sqm = square_mod (m, n1);
            EXPECT_EQ ((sqm), encrypted12) << "decrypted message " << m << " squared -> " << sqm << " != " << m2 << " mod " << n1;
        }

        for (const auto &m : decrypted221) {
            auto sqm = square_mod (m, n2);
            EXPECT_EQ ((sqm), encrypted21) << "decrypted message " << m << " squared -> " << sqm << " != " << m1 << " mod " << n2;
        }

        for (const auto &m : decrypted222) {
            auto sqm = square_mod (m, n2);
            EXPECT_EQ ((sqm), encrypted22) << "decrypted message " << m << " squared -> " << sqm << " != " << m2 << " mod " << n2;
        }

        EXPECT_TRUE ((contains (decrypted111, m1)));
        EXPECT_TRUE ((contains (decrypted112, m2)));

        EXPECT_TRUE ((contains (decrypted221, m1)));
        EXPECT_TRUE ((contains (decrypted222, m2)));

    }

    using rabin_test_cases = ::testing::Types<
        //Rabin<uint32, 12>, Rabin<uint32, 13>, Rabin<uint32, 15>,
        Rabin<uint32, 16>, Rabin<uint32, 17>, Rabin<uint32, 18>,
        //Rabin<int32, 16>, Rabin<int32, 17>, Rabin<int32, 18>,
        Rabin<uint64, 16>, Rabin<uint64, 17>, Rabin<uint64, 18>,
        //Rabin<int64, 16>, Rabin<int64, 17>, Rabin<int64, 18>,
        Rabin<uint160, 16>, Rabin<uint160, 17>, Rabin<uint160, 18>,
        //Rabin<int160, 16>, Rabin<int160, 17>, Rabin<int160, 18>,
        Rabin<uint256, 16>, Rabin<uint256, 17>, Rabin<uint256, 18>,
        //Rabin<int256, 16>, Rabin<int256, 17>, Rabin<int256, 18>,
        Rabin<N, 16>, Rabin<N, 17>, Rabin<N, 18>/*,
        Rabin<Z, 16>, Rabin<Z, 17>, Rabin<Z, 18>*/>;

    template <typename X> struct RabinTest;

    template <typename N, size_t bits>
    struct RabinTest<Rabin<N, bits>> : ::testing::Test {
        using system = Rabin<N, bits>;
        using number = N;
    };

    TYPED_TEST_SUITE (RabinTest, rabin_test_cases);

    random::std_random<std::default_random_engine> r_rab {49294805793};

    TYPED_TEST (RabinTest, WorkedExample) {

        using Rabin = typename TestFixture::system;
        using N = typename TestFixture::number;

        auto P = math::number::is_prime (r_rab, N (7));
        auto Q = math::number::is_prime (r_rab, N (11));

        typename Rabin::secret z {P, Q};
        typename Rabin::pubkey y = z.to_public ();

        N message = N (20);

        auto encrypted = y.encrypt (message);
        auto decrypted = z.decrypt (encrypted);

        std::cout << "encrypt " << message << " to " << encrypted << std::endl;
        std::cout << "decrypt " << message << " to " << decrypted << std::endl;

        EXPECT_TRUE (contains (decrypted, 20));


    }

    TYPED_TEST (RabinTest, Rabin) {

        using System = typename TestFixture::system;
        test_Rabin<System, typename TestFixture::number> (r_rab);
    }

}

