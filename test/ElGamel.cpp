// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include <crypto/ElGamel.hpp>

namespace crypto {

    template <auto gen, auto order> void test_ElGamel (random::source &oo, const N &m1, const N &m2) {

        ASSERT_NE (m1, m2);

        using EG = crypto::ElGamel<gen, order>;

        // generate keys
        auto secret1 = EG::generate (oo);
        auto secret2 = EG::generate (oo);

        EXPECT_TRUE (secret1.valid ());
        EXPECT_TRUE (secret2.valid ());

        EXPECT_NE (secret1, secret2);

        // generate public key
        auto pubkey1 = secret1.to_public ();
        auto pubkey2 = secret2.to_public ();

        EXPECT_NE (pubkey1, pubkey2);

    }

}

