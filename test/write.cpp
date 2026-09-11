// Copyright (c) 2025 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <data/bytes.hpp>
#include <data/array.hpp>
#include <data/numbers.hpp>

#include <crypto/hash/MD5.hpp>
#include <crypto/MAC.hpp>
#include <crypto/MAC/HMAC.hpp>

namespace crypto::hash {

    // we don't have to test that the hash is correct, just that the interface works.
    TEST (Write, Hash) {

        // write a list of bytes
        EXPECT_NO_THROW (write<MD5> ());
        EXPECT_NO_THROW ((write<MD5> (byte (0x76))));
        EXPECT_NO_THROW ((write<MD5> (byte (0x76), byte (0x01))));
        EXPECT_NO_THROW ((write<MD5> (byte (0x76), uint32_little (12))));

        // write to bytes with function
        EXPECT_NO_THROW (write<MD5> ([](auto &&w) {}));
        EXPECT_NO_THROW ((write<MD5> ([](auto &&w) { w << byte (0x76); })));
        EXPECT_NO_THROW ((write<MD5> ([](auto &&w) { w << byte (0x76) << byte (0x01); })));
        EXPECT_NO_THROW ((write<MD5> ([](auto &&w) { w << byte (0x76) << uint32_little (12); })));

    }
}

namespace crypto::MAC {

    TEST (Write, HMAC) {

        const cipher::symmetric_key<5> key {encoding::hex::fixed<5> {"abcdef0102"}};

        // write a list of bytes
        EXPECT_NO_THROW (write<HMAC<hash::MD5>> (key));
        EXPECT_NO_THROW ((write<HMAC<hash::MD5>> (key, byte (0x76))));
        EXPECT_NO_THROW ((write<HMAC<hash::MD5>> (key, byte (0x76), byte (0x01))));
        EXPECT_NO_THROW ((write<HMAC<hash::MD5>> (key, byte (0x76), uint32_little (12))));

        // write to bytes with function
        EXPECT_NO_THROW (write<writer<HMAC<hash::MD5>>> (key, [](auto &&w) {}));
        EXPECT_NO_THROW ((write<writer<HMAC<hash::MD5>>> (key, [](auto &&w) { w << byte (0x76); })));
        EXPECT_NO_THROW ((write<writer<HMAC<hash::MD5>>> (key, [](auto &&w) { w << byte (0x76) << byte (0x01); })));
        EXPECT_NO_THROW ((write<writer<HMAC<hash::MD5>>> (key, [](auto &&w) { w << byte (0x76) << uint32_little (12); })));

    }
}



