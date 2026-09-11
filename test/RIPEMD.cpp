// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include <crypto/hash/RIPEMD.hpp>

namespace crypto {
    void RIPEMD_test_case (std::string test, string dig) {
        EXPECT_EQ (crypto::RIPEMD_160 (test), hash::digest<20> {dig});
        EXPECT_EQ (hash::calculate<crypto::hash::RIPEMD<20>> (test), hash::digest<20> {dig});
        EXPECT_EQ (hash::calculate<hash::writer<crypto::hash::RIPEMD<20>>> (test), hash::digest<20> {dig});

        hash::digest<20> result; {
            hash::writer<crypto::hash::RIPEMD<20>> w {result};
            w << test;
        }

        EXPECT_EQ (result, hash::digest<20> {dig});
    }

    // from https://rosettacode.org/wiki/RIPEMD-160
    TEST (Hash, RIPEMD) {

        RIPEMD_test_case ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31");
        RIPEMD_test_case ("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
        RIPEMD_test_case ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
        RIPEMD_test_case ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36");
        RIPEMD_test_case ("abcdefghijklmnopqrstuvwxyz",
                          "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
        RIPEMD_test_case ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                          "12a053384a9c0c88e405a06c27dcf49ada62eb2b");

    }
}

