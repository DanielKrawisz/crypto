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


    template <typename N, size_t bits> void test_Rabin (random::source &oo) {

        using Rabin = crypto::Rabin<N, bits>;

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

        auto decrypted111 = secret1.decrypt (encrypted11);
        auto decrypted112 = secret1.decrypt (encrypted12);

        EXPECT_TRUE ((contains (decrypted111, m1)));
        EXPECT_TRUE ((contains (decrypted112, m2)));

        auto decrypted121 = secret1.decrypt (encrypted21);
        auto decrypted122 = secret1.decrypt (encrypted22);

        EXPECT_FALSE ((contains (decrypted121, m1)));
        EXPECT_FALSE ((contains (decrypted122, m2)));

        auto decrypted211 = secret2.decrypt (encrypted11);
        auto decrypted212 = secret2.decrypt (encrypted12);

        EXPECT_FALSE ((contains (decrypted211, m1)));
        EXPECT_FALSE ((contains (decrypted212, m2)));

        auto decrypted221 = secret2.decrypt (encrypted21);
        auto decrypted222 = secret2.decrypt (encrypted22);

        EXPECT_TRUE ((contains (decrypted221, m1)));
        EXPECT_TRUE ((contains (decrypted222, m2)));

    }

    TEST (Rabin, Rabin) {
        random::std_random<std::default_random_engine> r {49294805793};
        test_Rabin<uint32, 16> (r);
        test_Rabin<uint64, 17> (r);
        //test_Rabin<uint256, 18> (r);
        //test_Rabin<N, 19> (r);
        //test_Rabin<N_bytes_big, 20> (r);

        // TODO This is too slow. We need to make it faster before we can actually run this test.
        // test_Rabin<Z_bytes_BC_little, 21> (r, 5, 6);
    }

}

