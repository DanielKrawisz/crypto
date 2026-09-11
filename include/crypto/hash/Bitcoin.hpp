// Copyright (c) 2021-2022 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_HASH_BITCOIN
#define CRYPTO_HASH_BITCOIN

#include <crypto/hash/SHA2.hpp>
#include <crypto/hash/RIPEMD.hpp>

namespace crypto {

    hash::digest160 Bitcoin_160 (byte_slice);
    hash::digest256 Bitcoin_256 (byte_slice);
    hash::digest160 Bitcoin_160 (string_view);
    hash::digest256 Bitcoin_256 (string_view);

    hash::digest160 inline Bitcoin_160 (string_view b) {
        return Bitcoin_160 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

    hash::digest256 inline Bitcoin_256 (string_view b) {
        return Bitcoin_256 (byte_slice {(const byte *) (b.data ()), b.size ()});
    }

}

namespace crypto::hash {
    
    // Bitcoin hash 160 is difined to be RIPEMD_160 * SHA2_256
    template<> struct Bitcoin<20> {

        SHA2<32> Engine;
        
        constexpr static size_t DigestSize = 20;
        constexpr static size_t BlockSize = 64;
        
        Bitcoin () : Engine {} {}
        
        Bitcoin<20> &Update (const byte *b, size_t x) {
            Engine.Update (b, x);
            return *this;
        }
        
        void Final (byte b[BlockSize]) {
            byte x[32];
            Engine.Final (x);
            CRIPEMD160 ().Update (x, 32).Final (b);
        }

        Bitcoin<20> &Restart () {
            Engine.Restart ();
            return *this;
        }
    };
    
    // Bitcoin hash 256 is difined to be SHA2_256 * SHA_256
    template<> struct Bitcoin<32> {
        
        SHA2<32> Engine;
        
        constexpr static size_t DigestSize = 32;
        constexpr static size_t BlockSize = 64;
        
        Bitcoin () : Engine {} {}
        
        Bitcoin<32> &Update (const byte *b, size_t x) {
            Engine.Update (b, x);
            return *this;
        }
        
        void Final (byte b[BlockSize]) {
            byte x[32];
            Engine.Final (x);
            CSHA256 ().Update (x, 32).Final (b);
        }

        Bitcoin<32> &Restart () {
            Engine.Restart ();
            return *this;
        }
    };

    using Bitcoin160_writer = hash::writer<Bitcoin<20>>;
    using Bitcoin256_writer = hash::writer<Bitcoin<32>>;

}

namespace crypto {

    hash::digest160 inline Bitcoin_160 (byte_slice b) {
        return hash::calculate<hash::Bitcoin<20>> (b);
    }

    hash::digest256 inline Bitcoin_256 (byte_slice b) {
        return hash::calculate<hash::Bitcoin<32>> (b);
    }
}

#endif


