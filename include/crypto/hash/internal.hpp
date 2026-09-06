// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_HASH_GENERAL
#define CRYPTO_HASH_GENERAL

#include <data/hash.hpp>
#include <data/integral.hpp>

#include <crypto/one_way.hpp>
#include <cryptopp/scrypt.h>

// Here we collect hash functions that are intended to
// work internally rather than in public.

// general purpose hash functions (non-cryptographic)
namespace data {

    // the following are not yet supported.
    uint32_little xxHash_32 (byte_slice, uint32_little seed);
    uint32_little xxHash_32 (string_view, uint32_little seed);

    uint64_little xxHash_64 (byte_slice, uint64_little seed);
    uint64_little xxHash_64 (string_view, uint64_little seed);

    uint32_little xxHash3_32 (byte_slice, uint32_little seed);
    uint32_little xxHash3_32 (string_view, uint32_little seed);

    uint64_little xxHash3_64 (byte_slice, uint64_little seed);
    uint64_little xxHash3_64 (string_view, uint64_little seed);

    uint64_little xxHash3_128 (byte_slice, uint64_little seed);
    uint64_little xxHash3_128 (string_view, uint64_little seed);

    uint32_little MurmurHash3_x86_32 (byte_slice, uint32 seed);
    uint32_little MurmurHash3_x86_32 (string_view, uint32 seed);

    uint128_little MurmurHash3_x86_128 (byte_slice, uint32 seed);
    uint128_little MurmurHash3_x86_128 (string_view, uint32 seed);

    uint128_little MurmurHash3_x64_128 (byte_slice, uint32 seed);
    uint128_little MurmurHash3_x64_128 (string_view, uint32 seed);
}

// password hashing functions.
namespace crypto {

    template <size_t output_size>
    byte_array<output_size> Argon2id (
        uint32 time_cost,
        uint32 mem_cost,
        uint32 parallelism,
        byte_slice password,
        byte_slice salt);

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

#endif
