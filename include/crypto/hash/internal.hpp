// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_HASH_GENERAL
#define CRYPTO_HASH_GENERAL

#include <data/hash.hpp>
#include <data/integral.hpp>

#include <crypto/one_way.hpp>
#include <cryptopp/scrypt.h>

// Here we collect general hash functions that we intend to support in a future release.

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

#endif
