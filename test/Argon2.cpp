// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include <crypto/hash/Argon2.hpp>

namespace crypto {

    // from RFC 9106
    TEST (Internal, Argon2) {

        const size_t tag_length =  32;
        uint32 memory_kb        =  32;
        uint32 passes           =   3;
        uint32 parallelism      =   4;

        bytes password = *encoding::hex::read (
            "0101010101010101"
            "0101010101010101"
            "0101010101010101"
            "0101010101010101");

        bytes salt = *encoding::hex::read (
            "02020202020202020202020202020202");

        bytes secret = *encoding::hex::read (
            "0303030303030303");

        bytes data = *encoding::hex::read (
            "040404040404040404040404");

        {
            byte_array<tag_length> tag = byte_array<tag_length> (encoding::hex::fixed<tag_length> (
                "512b391b6f116297"
                "5371d30919734294"
                "f868e3be3984f3c1"
                "a13a4db9fabe4acb"));

            EXPECT_EQ ((Argon2d<tag_length> (passes, memory_kb, parallelism, password, salt, secret, data)), tag);
        }

        {
            byte_array<tag_length> tag = byte_array<tag_length> (encoding::hex::fixed<tag_length> (
                "c814d9d1dc7f37aa"
                "13f0d77f2494bda1"
                "c8de6b016dd388d2"
                "9952a4c4672b6ce8"));

            EXPECT_EQ ((Argon2i<tag_length> (passes, memory_kb, parallelism, password, salt, secret, data)), tag);
        }

        {
            byte_array<tag_length> tag = byte_array<tag_length> (encoding::hex::fixed<tag_length> (
                "0d640df58d78766c"
                "08c037a34a8b53c9"
                "d01ef0452d75b65e"
                "b52520e96b01e659"));

            EXPECT_EQ ((Argon2id<tag_length> (passes, memory_kb, parallelism, password, salt, secret, data)), tag);
        }
    }
}
