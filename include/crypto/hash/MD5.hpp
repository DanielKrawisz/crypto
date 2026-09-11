// Copyright (c) 2022-26 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <crypto/hash.hpp>

// We use weak functions such as SHA1 and MD5.
// These functions are still in widespread use
// as regular hash functions.
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptopp/md5.h"

#include <crypto/hash/dep/engine.hpp>

namespace crypto {

    // MD5 is depricated as a cryptographic hash function but still used
    // as a general purpose hash function.
    hash::digest128 MD5 (byte_slice);
    hash::digest128 MD5 (string_view);
}

namespace crypto::hash {

    struct MD5 : CryptoPP::engine<CryptoPP::Weak::MD5> {};
    using MD5_writer = hash::writer<MD5>;

}

namespace crypto {

    hash::digest128 inline MD5 (string_view b) {
        return MD5 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest128 inline MD5 (byte_slice b) {
        return hash::calculate<hash::MD5> (b);
    }
}

