// Copyright (c) 2021-2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_HASH_CRYPTOPP_TF_FROM_ENGINE
#define CRYPTO_HASH_CRYPTOPP_TF_FROM_ENGINE

#include "cryptopp/cryptlib.h"

namespace crypto::hash::CryptoPP {
    using namespace ::CryptoPP;

    // turn an Engine into a cryptopp HashTransformation.
    template <Engine engine>
    struct tf_from_engine final : HashTransformation {
        constexpr static unsigned int DIGESTSIZE = engine::DigestSize;
        constexpr static unsigned int BLOCKSIZE = engine::BlockSize;

        engine Engine;

        void Update (const byte *input, size_t length) override {
            Engine.Update (input, length);
        }

        unsigned int DigestSize () const override {
            return DIGESTSIZE;
        }

        unsigned int BlockSize () const override {
            return BLOCKSIZE;
        }

        void TruncatedFinal (byte *digest, size_t digestSize) override {
            if (digestSize < DIGESTSIZE) {
                byte fin[DIGESTSIZE];
                Engine.Final (fin);
                std::copy (fin, fin + digestSize, digest);
            } else Engine.Final (digest);
            Restart ();
        }

        void Restart () override {
            Engine.Restart ();
        }

        static std::string StaticAlgorithmName () {
            return "unknown";
        }

        tf_from_engine () = default;

        tf_from_engine (const tf_from_engine &) = delete;
        tf_from_engine &operator = (const tf_from_engine &) = delete;

        tf_from_engine (tf_from_engine &&) = delete;
        tf_from_engine &operator = (tf_from_engine &&) = delete;
    };
}

#endif
