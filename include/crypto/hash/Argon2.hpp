// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/bytes.hpp>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/err.h>

// a password hashing functions.
namespace crypto {
    using namespace data;

    enum argon_type {d, i, id};

    template <argon_type type, size_t tag_length>
    byte_array<tag_length> Argon2 (
        uint32 passes,                  // t: number of passes
        uint32 memory_kb,               // m: memory size in KiB
        uint32 parallelism,             // p: number of lanes
        byte_slice password,            // P: password
        byte_slice salt,                // S: salt (nonce)
        byte_slice secret = {},         // K: optional secret value
        byte_slice associated_data = {} // X: optional associated data
    );

    template <size_t tag_length>
    byte_array<tag_length> inline Argon2i (
        uint32 passes,
        uint32 memory_kb,
        uint32 parallelism,
        byte_slice password,
        byte_slice salt,
        byte_slice secret = {},
        byte_slice additional = {}) {
        return Argon2<i, tag_length> (passes, memory_kb, parallelism, password, salt, secret, additional);
    }

    template <size_t tag_length>
    byte_array<tag_length> inline Argon2d (
        uint32 passes,
        uint32 memory_kb,
        uint32 parallelism,
        byte_slice password,
        byte_slice salt,
        byte_slice secret = {},
        byte_slice additional = {}) {
        return Argon2<d, tag_length> (passes, memory_kb, parallelism, password, salt, secret, additional);
    }

    template <size_t tag_length>
    byte_array<tag_length> inline Argon2id (
        uint32 passes,
        uint32 memory_kb,
        uint32 parallelism,
        byte_slice password,
        byte_slice salt,
        byte_slice secret = {},
        byte_slice additional = {}) {
        return Argon2<id, tag_length> (passes, memory_kb, parallelism, password, salt, secret, additional);
    }

    template <argon_type type, size_t tag_length>
    byte_array<tag_length> Argon2 (
        uint32 passes,
        uint32 memory_kb,
        uint32 parallelism,
        byte_slice password,
        byte_slice salt,
        byte_slice secret,
        byte_slice additional
    ) {
        const char *name;

        switch (type) {
            case i:  name = "ARGON2I";  break;
            case d:  name = "ARGON2D";  break;
            case id: name = "ARGON2ID"; break;
        }

        EVP_KDF *kdf = EVP_KDF_fetch (nullptr, name, nullptr);
        if (kdf == nullptr)
            throw std::runtime_error ("unable to fetch Argon2");

        EVP_KDF_CTX *ctx = EVP_KDF_CTX_new (kdf);
        EVP_KDF_free (kdf);

        if (ctx == nullptr)
            throw std::runtime_error ("unable to create Argon2 context");

        OSSL_PARAM params[] {
            OSSL_PARAM_construct_uint32 (
                OSSL_KDF_PARAM_ITER,
                &passes
            ),
            OSSL_PARAM_construct_uint32 (
                OSSL_KDF_PARAM_ARGON2_MEMCOST,
                &memory_kb
            ),
            OSSL_PARAM_construct_uint32 (
                OSSL_KDF_PARAM_ARGON2_LANES,
                &parallelism
            ),
            OSSL_PARAM_construct_octet_string (
                OSSL_KDF_PARAM_PASSWORD,
                const_cast<unsigned char *> (
                    reinterpret_cast<const unsigned char *> (password.data ())
                ),
                password.size ()
            ),
            OSSL_PARAM_construct_octet_string (
                OSSL_KDF_PARAM_SALT,
                const_cast<unsigned char *> (
                    reinterpret_cast<const unsigned char *> (salt.data ())
                ),
                salt.size ()
            ),
            OSSL_PARAM_construct_octet_string (
                OSSL_KDF_PARAM_SECRET,
                const_cast<unsigned char *> (
                    reinterpret_cast<const unsigned char *> (secret.data ())
                ),
                secret.size()
            ),
            OSSL_PARAM_construct_octet_string (
                OSSL_KDF_PARAM_ARGON2_AD,
                const_cast<unsigned char *> (
                    reinterpret_cast<const unsigned char *> (additional.data ())
                ),
                additional.size ()
            ),
            OSSL_PARAM_construct_end ()
        };

        byte_array<tag_length> result;

        if (EVP_KDF_derive (
                ctx,
                reinterpret_cast<unsigned char *> (result.data ()),
                tag_length,
                params
            ) != 1) {
            EVP_KDF_CTX_free (ctx);
            throw std::runtime_error ("Argon2 derivation failed");
        }

        EVP_KDF_CTX_free (ctx);

        return result;
    }

}


