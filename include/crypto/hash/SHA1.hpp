// Copyright (c) 2022-26 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <crypto/hash.hpp>
#include <sv/crypto/sha1.h>

#include <crypto/hash/dep/engine.hpp>

namespace crypto {

    // SHA1 is depricated as a cryptographic hash function but  still
    // standard and still useful for non-cryptographic purposes things.
    // SHA1 is not depricated for use with Hash_DRBG.
    hash::digest160 SHA1 (byte_slice);
    hash::digest160 SHA1 (string_view);
}


namespace crypto::hash {

    struct SHA1 : CSHA1 {};

    using SHA1_writer = hash::writer<SHA1>;

}

namespace crypto {

    hash::digest160 inline SHA1 (string_view b) {
        return SHA1 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest160 inline SHA1 (byte_slice b) {
        return hash::calculate<hash::SHA1> (b);
    }

}
