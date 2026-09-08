// Copyright (c) 2021-2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_HASH_OPENSSL
#define CRYPTO_HASH_OPENSSL

#include <crypto/hash/reference.hpp>
#include <openssl/evp.h>

namespace crypto::hash::OpenSSL {

    template <size_t output_size>
    struct engine {
        constexpr static const size_t DigestSize = output_size;

        using init_function =
            int (*) (EVP_MD_CTX *);

        EVP_MD_CTX *Context;

        init_function Init;

        engine (
            init_function init):

            Context {EVP_MD_CTX_new ()},
            Init {init} {

            Restart ();
        }

        ~engine () {
            EVP_MD_CTX_free (Context);
        }

        engine (const engine &) = delete;
        engine &operator= (const engine &) = delete;

        void Restart () {
            if (!Init (Context))
                throw exception {} << "could not update hash";
        }

        void Update (const byte *data, size_t size) {
            if (!EVP_DigestUpdate (Context, data, size))
                throw exception {} << "could not update hash";
        }

        void Final (byte result[output_size]) {
            unsigned int size;

            if (!EVP_DigestFinal_ex (Context, result, &size))
                throw exception {} << "could not write hash";

            assert (size == output_size);
        }
    };

}

namespace crypto::hash {

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

    hash::digest224 inline SHA2_512_224 (byte_slice x) {
        return hash::calculate<hash::SHA2<64, 28>> (x);
    }

    hash::digest256 inline SHA2_512_256 (byte_slice x) {
        return hash::calculate<hash::SHA2<64, 32>> (x);
    }
}

#endif
