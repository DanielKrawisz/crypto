// Copyright (c) 2021-2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

// We use weak functions such as SHA1 and MD5.
// These functions are still in widespread use
// as regular hash functions.
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptopp/cryptlib.h"
#include "cryptopp/ripemd.h"
#include <sv/crypto/ripemd160.h>

#include <crypto/hash/dep/engine.hpp>

namespace crypto {

    hash::digest128 RIPEMD_128 (byte_slice);
    hash::digest128 RIPEMD_128 (string_view);
    hash::digest160 RIPEMD_160 (byte_slice);
    hash::digest160 RIPEMD_160 (string_view);
    hash::digest256 RIPEMD_256 (byte_slice);
    hash::digest256 RIPEMD_256 (string_view);
    hash::digest320 RIPEMD_320 (byte_slice);
    hash::digest320 RIPEMD_320 (string_view);

}

namespace crypto::hash {

    template <> struct RIPEMD<16> : CryptoPP::engine<CryptoPP::RIPEMD128> {};

    template <> struct RIPEMD<20> : CRIPEMD160 {};

    template <> struct RIPEMD<32> : CryptoPP::engine<CryptoPP::RIPEMD256> {};

    template <> struct RIPEMD<40> : CryptoPP::engine<CryptoPP::RIPEMD320> {};
    
}

namespace crypto {

    hash::digest128 inline RIPEMD_128 (string_view b) {
        return RIPEMD_128 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest160 inline RIPEMD_160 (string_view b) {
        return RIPEMD_160 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest256 inline RIPEMD_256 (string_view b) {
        return RIPEMD_256 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest320 inline RIPEMD_320 (string_view b) {
        return RIPEMD_320 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest128 inline RIPEMD_128 (byte_slice b) {
        return hash::calculate<hash::RIPEMD<16>> (b);
    }

    hash::digest160 inline RIPEMD_160 (byte_slice b) {
        return hash::calculate<hash::RIPEMD<20>> (b);
    }

    hash::digest256 inline RIPEMD_256 (byte_slice b) {
        return hash::calculate<hash::RIPEMD<32>> (b);
    }

    hash::digest320 inline RIPEMD_320 (byte_slice b) {
        return hash::calculate<hash::RIPEMD<40>> (b);
    }

}
