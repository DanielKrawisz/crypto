// Copyright (c) 2022-26 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_HASH_FUNCTIONS
#define CRYPTO_HASH_FUNCTIONS

#include <data/hash.hpp>

#include <crypto/one_way.hpp>

// this file collects hash function declarations that can be used as references,
// secure or otherwise. In other words, the digest of the function can be used
// to denote a string in public for other people to know what you mean.

// general purpose hash functions (non-cryptographic)
namespace data {

    uint32_little CRC32 (byte_slice);
    uint32_little CRC32 (string_view);

    uint32_little CRC32C (byte_slice);
    uint32_little CRC32C (string_view);
}

namespace crypto::hash {
    using namespace data::hash;
}

namespace crypto {

    // supported cryptographic hash functions.

    // SHA1 and MD5 are depricated but still standard and still useful for some things.
    hash::digest160 SHA1 (byte_slice);
    hash::digest160 SHA1 (string_view);

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

}

namespace data::hash {
    struct CRC32;
    struct CRC32C;
}

namespace crypto::hash {

    template <typename W>
    concept Writer = data::hash::Writer<W> && requires {
        requires byte (W::Security) >= byte (security::modern) ;
    };
    
    // All of these satisfy hash::Engine.
    struct SHA1;
    struct MD5;
    template <size_t digest_size> struct RIPEMD;
    template <size_t ...> struct SHA2;
    template <size_t digest_size> struct SHA3;
    template <size_t digest_size> struct Bitcoin;

    template <> struct RIPEMD<16>;
    template <> struct RIPEMD<20>;
    template <> struct RIPEMD<32>;
    template <> struct RIPEMD<40>;

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

}

namespace data {

    uint32_little inline CRC32 (string_view b) {
        return CRC32 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    uint32_little inline CRC32C (string_view b) {
        return CRC32C (byte_slice {(const byte *) (b.data ()), b.size ()});
    }
}

namespace crypto {

    hash::digest160 inline SHA1 (string_view b) {
        return SHA1 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest128 inline MD5 (string_view b) {
        return MD5 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest224 inline SHA2_224 (string_view b) {
        return SHA2_224 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest256 inline SHA2_256 (string_view b) {
        return SHA2_256 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest384 inline SHA2_384 (string_view b) {
        return SHA2_384 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest512 inline SHA2_512 (string_view b) {
        return SHA2_512 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest224 inline SHA2_512_224 (string_view b) {
        return SHA2_512_224 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest256 inline SHA2_512_256 (string_view b) {
        return SHA2_512_256 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    template <size_t size> hash::digest<size> SHA3 (string_view b) {
        return SHA3<size> (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest224 inline SHA3_224 (string_view b) {
        return SHA3_224 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest256 inline SHA3_256 (string_view b) {
        return SHA3_256 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest384 inline SHA3_384 (string_view b) {
        return SHA3_384 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest512 inline SHA3_512 (string_view b) {
        return SHA3_512 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest128 inline RIPEMD_128 (string_view b) {
        return RIPEMD_128 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest160 inline RIPEMD_160 (string_view b) {
        return RIPEMD_160 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest256 inline RIPEMD_256 (string_view b) {
        return RIPEMD_256 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest320 inline RIPEMD_320 (string_view b) {
        return RIPEMD_320 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest160 inline Bitcoin_160 (string_view b) {
        return Bitcoin_160 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest256 inline Bitcoin_256 (string_view b) {
        return Bitcoin_256 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

}

#endif

