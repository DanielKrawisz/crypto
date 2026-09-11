// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include <crypto/hash/MD5.hpp>

namespace crypto {

    void MD5_test_case (std::string test, string expected) {

        EXPECT_EQ (crypto::MD5 (test), hash::digest<16> {expected});
        EXPECT_EQ (hash::calculate<crypto::hash::MD5> (test), hash::digest<16> {expected});
        EXPECT_EQ (hash::calculate<hash::writer<crypto::hash::MD5>> (test), hash::digest<16> {expected});

        hash::digest<16> result = build_with<hash::digest<16>, hash::writer<crypto::hash::MD5>> ([&test] (auto &w) {
            w << test;
        });

        EXPECT_EQ (result, hash::digest<16> {expected});

    }

    TEST (Hash, MD5) {

        MD5_test_case ("", "d41d8cd98f00b204e9800998ecf8427e");
        MD5_test_case ("a", "0cc175b9c0f1b6a831c399e269772661");
        MD5_test_case ("abc", "900150983cd24fb0d6963f7d28e17f72");
        MD5_test_case ("message digest", "f96b697d7cb7938d525a2f31aaf161d0");

        MD5_test_case ("abcdefghijklmnopqrstuvwxyz",
                       "c3fcd3d76192e4007dfb496cca67e13b");

        MD5_test_case ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                       "d174ab98d277d9f5a5611c2c9f419d9f");

        MD5_test_case ("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                       "57edf4a22be3c955ac49da2e2107b67a");

    }
}
