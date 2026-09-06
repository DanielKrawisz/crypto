// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_HASH_GENERAL
#define CRYPTO_HASH_GENERAL

#include <data/hash.hpp>
#include <data/integral.hpp>

#include <crypto/one_way.hpp>

#include <crypto/hash/cryptopp/engine.hpp>

#include "cryptopp/crc.h"

// general purpose hash functions (non-cryptographic)
namespace data {

    uint32_little CRC32 (byte_slice);
    uint32_little CRC32 (string_view);

    uint32_little CRC32C (byte_slice);
    uint32_little CRC32C (string_view);

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

namespace data::hash {

    // All of these satisfy hash::Engine.

    struct CRC32 : crypto::hash::CryptoPP::engine<CryptoPP::CRC32> {};

    struct CRC32C : crypto::hash::CryptoPP::engine<CryptoPP::CRC32C> {};
}

namespace data {

    uint32_little inline CRC32 (string_view b) {
        return CRC32 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    uint32_little inline CRC32C (string_view b) {
        return CRC32C (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    uint32_little inline CRC32 (byte_slice b) {
        hash::CRC32 w {};
        w.Update (b.data (), b.size ());
        uint32_little d;
        w.Final (d.data ());
        return d;
    }

    uint32_little inline CRC32C (byte_slice b) {
        hash::CRC32C w {};
        w.Update (b.data (), b.size ());
        uint32_little d;
        w.Final (d.data ());
        return d;
    }
}

#endif
