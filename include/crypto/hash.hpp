// Copyright (c) 2021-2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/hash.hpp>

#include <crypto/one_way.hpp>

// All supported reference hash functions (as opposed to internal or password hashes)
// are collected here.

namespace crypto::hash {
    using namespace data::hash;

    template <typename W>
    concept Writer = data::hash::Writer<W> && requires {
        requires byte (W::Security) >= byte (security::modern) ;
    };
}

// CRC is a family of general purpose (non-cryptographic) hash functions.
namespace data {

    uint32_little CRC32 (byte_slice);
    uint32_little CRC32 (string_view);

    uint32_little CRC32C (byte_slice);
    uint32_little CRC32C (string_view);
}

namespace crypto {

    // SHA1 is depricated as a cryptographic hash function but  still
    // standard and still useful for non-cryptographic purposes things.
    // SHA1 is not depricated for use with Hash_DRBG.
    hash::digest160 SHA1 (byte_slice);
    hash::digest160 SHA1 (string_view);

    // MD5 is depricated as a cryptographic hash function but still used
    // as a general purpose hash function.
    hash::digest128 MD5 (byte_slice);
    hash::digest128 MD5 (string_view);

    // secure hash functions for digital signatures.
    hash::digest224 SHA2_224 (byte_slice);
    hash::digest224 SHA2_224 (string_view);
    hash::digest256 SHA2_256 (byte_slice);
    hash::digest256 SHA2_256 (string_view);
    hash::digest384 SHA2_384 (byte_slice);
    hash::digest384 SHA2_384 (string_view);
    hash::digest512 SHA2_512 (byte_slice);
    hash::digest512 SHA2_512 (string_view);
    hash::digest224 SHA2_512_224 (byte_slice);
    hash::digest224 SHA2_512_224 (string_view);
    hash::digest256 SHA2_512_256 (byte_slice);
    hash::digest256 SHA2_512_256 (string_view);

    hash::digest128 RIPEMD_128 (byte_slice);
    hash::digest128 RIPEMD_128 (string_view);
    hash::digest160 RIPEMD_160 (byte_slice);
    hash::digest160 RIPEMD_160 (string_view);
    hash::digest256 RIPEMD_256 (byte_slice);
    hash::digest256 RIPEMD_256 (string_view);
    hash::digest320 RIPEMD_320 (byte_slice);
    hash::digest320 RIPEMD_320 (string_view);

    hash::digest160 Bitcoin_160 (byte_slice);
    hash::digest256 Bitcoin_256 (byte_slice);
    hash::digest160 Bitcoin_160 (string_view);
    hash::digest256 Bitcoin_256 (string_view);

    template <size_t size> hash::digest<size> SHA3 (byte_slice);
    template <size_t size> hash::digest<size> SHA3 (string_view);

    hash::digest224 SHA3_224 (byte_slice);
    hash::digest224 SHA3_224 (string_view);
    hash::digest256 SHA3_256 (byte_slice);
    hash::digest256 SHA3_256 (string_view);
    hash::digest384 SHA3_384 (byte_slice);
    hash::digest384 SHA3_384 (string_view);
    hash::digest512 SHA3_512 (byte_slice);
    hash::digest512 SHA3_512 (string_view);

}

namespace data::hash {

    struct CRC32;
    struct CRC32C;
}

namespace crypto::hash {

    // All of these satisfy hash::Engine.
    struct MD5;
    template <size_t digest_size> struct RIPEMD;
    template <size_t ...> struct SHA2;
    template <size_t digest_size> struct SHA3;
    template <size_t digest_size> struct Bitcoin;

    template <> struct RIPEMD<16>;
    template <> struct RIPEMD<20>;
    template <> struct RIPEMD<32>;
    template <> struct RIPEMD<40>;

    using RIPEMD_128 = RIPEMD<16>;
    using RIPEMD_160 = RIPEMD<20>;
    using RIPEMD_256 = RIPEMD<32>;
    using RIPEMD_320 = RIPEMD<40>;

    template <> struct SHA2<28>;
    template <> struct SHA2<32>;
    template <> struct SHA2<48>;
    template <> struct SHA2<64>;
    template <> struct SHA2<64, 28>;
    template <> struct SHA2<64, 32>;

    using SHA2_224 = SHA2<28>;
    using SHA2_256 = SHA2<32>;
    using SHA2_384 = SHA2<48>;
    using SHA2_512 = SHA2<64>;
    using SHA2_512_224 = SHA2<64, 28>;
    using SHA2_512_256 = SHA2<64, 32>;

    using SHA3_224 = SHA3<28>;
    using SHA3_256 = SHA3<32>;
    using SHA3_384 = SHA3<48>;
    using SHA3_512 = SHA3<64>;

}

