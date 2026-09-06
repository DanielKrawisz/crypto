// Copyright (c) 2021-2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_HASH_CRYPTOPP
#define CRYPTO_HASH_CRYPTOPP

// We use weak functions such as SHA1 and MD5.
// These functions are still in widespread use
// as regular hash functions.
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptopp/cryptlib.h"
#include "cryptopp/ripemd.h"
#include "cryptopp/md5.h"
#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"
#include "cryptopp/crc.h"

#include <crypto/hash/cryptopp/engine.hpp>

namespace crypto::hash {
    
#ifndef USE_BITCOIND_HASH_FUNCTIONS
    struct SHA1 : CryptoPP::engine<CryptoPP::SHA1> {};
#endif

    struct MD5 : CryptoPP::engine<CryptoPP::Weak::MD5> {};

    template <> struct RIPEMD<16> : CryptoPP::engine<CryptoPP::RIPEMD128> {};

#ifndef USE_BITCOIND_HASH_FUNCTIONS
    template <> struct RIPEMD<20> : CryptoPP::engine<CryptoPP::RIPEMD160> {};
#endif

    template <> struct RIPEMD<32> : CryptoPP::engine<CryptoPP::RIPEMD256> {};

    template <> struct RIPEMD<40> : CryptoPP::engine<CryptoPP::RIPEMD320> {};

    template <> struct SHA2<28> : CryptoPP::engine<CryptoPP::SHA224> {};

#ifndef USE_BITCOIND_HASH_FUNCTIONS
    template <> struct SHA2<32> : CryptoPP::engine<CryptoPP::SHA256> {};
#endif

    template <> struct SHA2<48> : CryptoPP::engine<CryptoPP::SHA384> {};

    template <> struct SHA2<64> : CryptoPP::engine<CryptoPP::SHA512> {};

    template <size_t size> struct SHA3 : CryptoPP::engine<CryptoPP::SHA3_Final<size>> {};
    
}

namespace crypto {

#ifndef USE_BITCOIND_HASH_FUNCTIONS
    hash::digest160 inline SHA1 (byte_slice b) {
        return hash::calculate<hash::SHA1> (b);
    }
#endif
    hash::digest128 inline MD5 (byte_slice b) {
        return hash::calculate<hash::MD5> (b);
    }

    hash::digest128 inline RIPEMD_128 (byte_slice b) {
        return hash::calculate<hash::RIPEMD<16>> (b);
    }

#ifndef USE_BITCOIND_HASH_FUNCTIONS
    hash::digest160 inline RIPEMD_160 (byte_slice b) {
        return hash::calculate<hash::RIPEMD<20>> (b);
    }
#endif

    hash::digest256 inline RIPEMD_256 (byte_slice b) {
        return hash::calculate<hash::RIPEMD<32>> (b);
    }

    hash::digest320 inline RIPEMD_320 (byte_slice b) {
        return hash::calculate<hash::RIPEMD<40>> (b);
    }

    hash::digest224 inline SHA2_224 (byte_slice b) {
        return hash::calculate<hash::SHA2<28>> (b);
    }

#ifndef USE_BITCOIND_HASH_FUNCTIONS
    hash::digest256 inline SHA2_256 (byte_slice b) {
        return hash::calculate<hash::SHA2<32>> (b);
    }
#endif

    template <size_t size> hash::digest<size> inline SHA3 (byte_slice b) {
        return hash::calculate<hash::SHA3<size>> (b);
    }
    
    hash::digest384 inline SHA2_384 (byte_slice b) {
        return hash::calculate<hash::SHA2<48>> (b);
    }

    hash::digest512 inline SHA2_512 (byte_slice b) {
        return hash::calculate<hash::SHA2<64>> (b);
    }

    hash::digest224 inline SHA3_224 (byte_slice b) {
        return hash::calculate<hash::SHA3<28>> (b);
    }

    hash::digest256 inline SHA3_256 (byte_slice b) {
        return hash::calculate<hash::SHA3<32>> (b);
    }

    hash::digest384 inline SHA3_384 (byte_slice b) {
        return hash::calculate<hash::SHA3<48>> (b);
    }

    hash::digest512 inline SHA3_512 (byte_slice b) {
        return hash::calculate<hash::SHA2<64>> (b);
    }

}

namespace data::hash {

    // All of these satisfy hash::Engine.

    struct CRC32 : crypto::hash::CryptoPP::engine<CryptoPP::CRC32> {};

    struct CRC32C : crypto::hash::CryptoPP::engine<CryptoPP::CRC32C> {};
}

namespace data {

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


