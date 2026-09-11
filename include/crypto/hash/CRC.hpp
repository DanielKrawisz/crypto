// Copyright (c) 2022-26 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <crypto/hash.hpp>
#include "cryptopp/crc.h"
#include <crypto/hash/dep/engine.hpp>

// CRC is a family of general purpose (non-cryptographic) hash functions.
namespace data {

    uint32_little CRC32 (byte_slice);
    uint32_little CRC32 (string_view);

    uint32_little CRC32C (byte_slice);
    uint32_little CRC32C (string_view);

}

namespace data::hash {

    // These satisfy hash engine.
    struct CRC32 : crypto::hash::CryptoPP::engine<CryptoPP::CRC32> {};

    struct CRC32C : crypto::hash::CryptoPP::engine<CryptoPP::CRC32C> {};

    using CRC32_writer = hash::writer<CRC32>;
    using CRC32C_writer = hash::writer<CRC32C>;

}

namespace data {

    uint32_little inline CRC32 (string_view b) {
        return CRC32 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    uint32_little inline CRC32C (string_view b) {
        return CRC32C (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    uint32_little inline CRC32 (byte_slice b) {
        hash::CRC32 w {};
        w.Update (b.data (), b.size ());
        uint32_little d;
        w.Final (d.data ());
        return d;
    }

    uint32_little inline CRC32C (byte_slice b) {
        hash::CRC32C w {};
        w.Update (b.data (), b.size ());
        uint32_little d;
        w.Final (d.data ());
        return d;
    }
}

