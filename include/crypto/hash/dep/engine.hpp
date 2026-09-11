// Copyright (c) 2021-2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_HASH_CRYPTOPP_ENGINE
#define CRYPTO_HASH_CRYPTOPP_ENGINE

#include "cryptopp/cryptlib.h"
#include <crypto/hash.hpp>

namespace crypto::hash::CryptoPP {
    using namespace ::CryptoPP;

    template <class Transform> struct engine;

    template <class Transform>
    requires std::derived_from<Transform, HashTransformation> && (Transform::BLOCKSIZE > 0)
    struct engine<Transform> : Transform {
        constexpr static size_t DigestSize = Transform::DIGESTSIZE;
        constexpr static size_t BlockSize = Transform::BLOCKSIZE;
        using Transform::Transform;
    };

    template <class Transform>
    requires std::derived_from<Transform, HashTransformation>
    struct engine<Transform> : Transform {
        constexpr static size_t DigestSize = Transform::DIGESTSIZE;
        using Transform::Transform;
    };

}

#endif

