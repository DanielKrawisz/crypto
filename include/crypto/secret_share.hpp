// Copyright (c) 2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_SECRET_SHARE
#define CRYPTO_SECRET_SHARE

#include <crypto/random.hpp>

namespace crypto {
    
    struct secret_share {
        byte Index;
        bytes Data;
    };
    
    cross<secret_share> secret_share_split (random::source &rng, const bytes &message, byte max, byte threshold);
    
    bytes secret_share_merge (cross<secret_share>, byte threshold);
    
}

#endif
