// Copyright (c) 2022-26 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_HASH_FUNCTIONS
#define CRYPTO_HASH_FUNCTIONS

#include <data/hash.hpp>

#include <crypto/one_way.hpp>

#include "cryptopp/sha3.h"
#include <crypto/hash/dep/engine.hpp>

namespace crypto {

    hash::digest224 SHA3_224 (byte_slice);
    hash::digest224 SHA3_224 (string_view);
    hash::digest256 SHA3_256 (byte_slice);
    hash::digest256 SHA3_256 (string_view);
    hash::digest384 SHA3_384 (byte_slice);
    hash::digest384 SHA3_384 (string_view);
    hash::digest512 SHA3_512 (byte_slice);
    hash::digest512 SHA3_512 (string_view);

    template <size_t size> hash::digest<size> SHA3 (byte_slice);
    template <size_t size> hash::digest<size> SHA3 (string_view);

}

namespace crypto::hash {
    template <size_t size> struct SHA3 : CryptoPP::engine<CryptoPP::SHA3_Final<size>> {};
}

namespace crypto {

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

    hash::digest224 inline SHA3_224 (byte_slice b) {
        return hash::calculate<hash::SHA3<224 / 8>> (b);
    }

    hash::digest256 inline SHA3_256 (byte_slice b) {
        return hash::calculate<hash::SHA3<256 / 8>> (b);
    }

    hash::digest384 inline SHA3_384 (byte_slice b) {
        return hash::calculate<hash::SHA3<384 / 8>> (b);
    }

    hash::digest512 inline SHA3_512 (byte_slice b) {
        return hash::calculate<hash::SHA3<512 / 8>> (b);
    }

}

#endif

