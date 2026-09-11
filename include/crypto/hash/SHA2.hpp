// Copyright (c) 2022-26 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <sv/crypto/sha1.h>
#include <sv/crypto/ripemd160.h>
#include <sv/crypto/sha256.h>
#include "cryptopp/sha.h"

#include <crypto/hash.hpp>
#include <crypto/hash/dep/openssl.hpp>
#include <crypto/hash/dep/engine.hpp>

namespace crypto {

    // NIST-approved secure hash functions for digital signatures.
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

}

namespace crypto::hash {

    template <> struct SHA2<28> : CryptoPP::engine<CryptoPP::SHA224> {};

    template <> struct SHA2<32> : CSHA256 {};

    template <> struct SHA2<48> : CryptoPP::engine<CryptoPP::SHA384> {};

    template <> struct SHA2<64> : CryptoPP::engine<CryptoPP::SHA512> {};

    template <> struct SHA2<64, 28> : OpenSSL::engine<28> {

        static int init (EVP_MD_CTX *ctx) {
            return EVP_DigestInit_ex (ctx, EVP_sha512_224 (), nullptr);
        }

        SHA2 (): OpenSSL::engine<28> {init} {}
    };

    template <> struct SHA2<64, 32> : OpenSSL::engine<32> {

        static int init (EVP_MD_CTX *ctx) {
            return EVP_DigestInit_ex (ctx, EVP_sha512_256 (), nullptr);
        }

        SHA2 (): OpenSSL::engine<32> {init} {}
    };

}

namespace crypto {

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

    hash::digest224 inline SHA2_224 (byte_slice b) {
        return hash::calculate<hash::SHA2<28>> (b);
    }

    hash::digest256 inline SHA2_256 (byte_slice b) {
        return hash::calculate<hash::SHA2<32>> (b);
    }

    hash::digest384 inline SHA2_384 (byte_slice b) {
        return hash::calculate<hash::SHA2<48>> (b);
    }

    hash::digest512 inline SHA2_512 (byte_slice b) {
        return hash::calculate<hash::SHA2<64>> (b);
    }

    hash::digest224 inline SHA2_512_224 (byte_slice x) {
        return hash::calculate<hash::SHA2<64, 28>> (x);
    }

    hash::digest256 inline SHA2_512_256 (byte_slice x) {
        return hash::calculate<hash::SHA2<64, 32>> (x);
    }
}

