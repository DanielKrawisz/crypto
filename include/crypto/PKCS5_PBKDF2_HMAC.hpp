// Copyright (c) 2020-2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_PKCS5_PBKDF2_HMAC
#define CRYPTO_PKCS5_PBKDF2_HMAC

#include <cryptopp/cryptlib.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

#include <crypto/hash.hpp>
#include <crypto/cipher.hpp>
#include <crypto/hash/dep/tf_from_engine.hpp>

namespace crypto {
    template <size_t size, hash::Engine Hash>
    cipher::symmetric_key<size> PKCS5_PBKDF2_HMAC (byte_slice password, int iterations, const bytes salt = {});

    template <size_t size, hash::Engine Hash>
    cipher::symmetric_key<size> PKCS5_PBKDF2_HMAC (byte_slice password, std::chrono::duration<float> seconds, const bytes salt = {});

    template <size_t size, hash::Engine Hash>
    cipher::symmetric_key<size> PKCS5_PBKDF2_HMAC (byte_slice password, int iterations, const bytes salt) {
        byte_array<size> key;

        using tf = std::conditional_t<std::derived_from<Hash, hash::CryptoPP::HashTransformation>,
            Hash,
            hash::CryptoPP::tf_from_engine<Hash>>;

        CryptoPP::PKCS5_PBKDF2_HMAC<tf> pbkdf;
        pbkdf.DeriveKey (key.data (), size, false, password.data (), password.size (), salt.data (), salt.size (), iterations, 0.0f);
        return key;
    }

    template <size_t size, hash::Engine Hash>
    cipher::symmetric_key<size> PKCS5_PBKDF2_HMAC (byte_slice password, std::chrono::duration<float> seconds, const bytes salt) {
        byte_array<size> key;

        using tf = std::conditional_t<std::derived_from<Hash, hash::CryptoPP::HashTransformation>,
            Hash,
            hash::CryptoPP::tf_from_engine<Hash>>;

        CryptoPP::PKCS5_PBKDF2_HMAC<tf> pbkdf;
        pbkdf.DeriveKey (key.data (), size, false, password.data (), password.size (), salt.data (), salt.size (), 0, seconds.count ());
        return key;
    }

}

#endif
