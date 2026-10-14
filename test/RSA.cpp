// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include <crypto/RSA.hpp>
#include <data/numbers.hpp>

namespace crypto {

    template <typename N, size_t bits> void test_RSA (random::source &oo, const N &m1, const N &m2) {

        ASSERT_NE (m1, m2);

        using RSA = crypto::RSA<N, bits>;

        // generate keys
        auto secret1 = RSA::generate (oo);
        auto secret2 = RSA::generate (oo);

        EXPECT_TRUE (secret1.valid ());
        EXPECT_TRUE (secret2.valid ());

        EXPECT_NE (secret1, secret2);

        // generate public key
        auto pubkey1 = secret1.to_public ();
        auto pubkey2 = secret2.to_public ();

        EXPECT_NE (pubkey1, pubkey2);

        auto encrypted11 = pubkey1.encrypt (m1);
        auto encrypted12 = pubkey1.encrypt (m2);
        auto encrypted21 = pubkey2.encrypt (m1);
        auto encrypted22 = pubkey2.encrypt (m2);

        EXPECT_NE (encrypted11, encrypted12);
        EXPECT_NE (encrypted11, encrypted21);
        EXPECT_NE (encrypted11, encrypted22);

        EXPECT_EQ (m1, pow_mod (encrypted11, secret1.D, math::nonzero {pubkey1.N}));
        EXPECT_EQ (m2, pow_mod (encrypted12, secret1.D, math::nonzero {pubkey1.N}));

        EXPECT_EQ (m1, pow_mod (encrypted21, secret2.D, math::nonzero {pubkey2.N}));
        EXPECT_EQ (m2, pow_mod (encrypted22, secret2.D, math::nonzero {pubkey2.N}));

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

    TEST (RSA, RSA) {
        random::std_random<std::default_random_engine> r {25767};
        test_RSA<uint32, 16> (r, 5, 6);
        test_RSA<uint64, 17> (r, 5, 6);
        test_RSA<uint256, 18> (r, 5, 6);
        test_RSA<N, 19> (r, 5, 6);
        test_RSA<N_bytes_big, 20> (r, 5, 6);

        // TODO This is too slow. We need to make it faster before we can actually run this test.
        // test_RSA<Z_bytes_BC_little, 21> (r, 5, 6);
    }

}

