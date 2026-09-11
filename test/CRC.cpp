// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <crypto/hash/CRC.hpp>

namespace crypto {

    TEST (Hash, CRC32) {
        EXPECT_EQ (CRC32 (""), uint32_little {0});
        EXPECT_EQ (CRC32 ("123456789"), uint32_little {0xCBF43926});
    }

    TEST (Hash, CRC32C) {
        EXPECT_EQ (CRC32C ("123456789"), uint32_little {0xe3069283});
        EXPECT_EQ (CRC32C (""), 0);
        EXPECT_EQ (CRC32C ("The quick brown fox jumps over the lazy dog"), 0x22620404);
    }

}
