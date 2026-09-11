// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <crypto/hash/Bitcoin.hpp>

namespace crypto {

    TEST (Hash, BitcoinHash) {
        bytes test = *encoding::hex::read ("00010203fdfeff");
        hash::digest256 expected {"be586c8b20dee549bdd66018c7a79e2b67bb88b7c7d428fa4c970976d2bec5ba"};

        EXPECT_EQ (crypto::Bitcoin_256 (test), expected);
    }

}

