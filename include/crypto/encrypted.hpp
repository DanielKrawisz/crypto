// Copyright (c) 2020-2022 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_ENCRYPTED
#define CRYPTO_ENCRYPTED

#include <data/iterable.hpp>
#include <data/stream.hpp>

#include <crypto/hash.hpp>

namespace crypto {

    template <size_t key_size> using symmetric_key = byte_array<key_size>;
    
    template <size_t block_size>
    using initialization_vector = byte_array<block_size>;

}

#endif

