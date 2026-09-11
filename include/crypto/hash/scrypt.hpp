// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/bytes.hpp>
#include <cryptopp/scrypt.h>

// a password hashing functions.
namespace crypto {
    using namespace data;

    // this is the only function in this file that is actually supported currently. The rest are for a future update.
    template <size_t output_size>
    byte_array<output_size> inline scrypt (
        byte_slice password,
        byte_slice salt,
        uint64 cost = 2,
        uint64 blockSize = 8,
        uint64 parallelization = 1) {
        byte_array<output_size> result;
        CryptoPP::Scrypt {}.DeriveKey (
            result.data (), result.size (),
            password.data (), password.size (),
            salt.data (), salt.size (),
            cost, blockSize, parallelization);
        return result;
    }

}

