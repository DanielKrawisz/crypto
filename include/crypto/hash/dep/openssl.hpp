// Copyright (c) 2021-2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_HASH_OPENSSL
#define CRYPTO_HASH_OPENSSL

#include <crypto/hash.hpp>
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

#endif
