// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/exception.hpp>
#include <data/numbers.hpp>
#include <data/math.hpp>
#include <data/math/algebra/finite_field.hpp>
#include <crypto/random.hpp>
#include <crypto/hash.hpp>

namespace crypto {

    template <size_t bits>
    struct Rabin {
        struct pubkey {};

        struct secret {
             pubkey to_public () const;
        };

        static secret generate (random::source &);
        static N encrypt (const pubkey &);
        static N decrypt (const secret &);
    };

    template <size_t bits>
    struct RabinWilliams {
        struct pubkey {};

        struct secret {
            pubkey to_public () const;
        };

        static secret generate (random::source &);
        static N sign (const N &, const secret &);
        static bool verify (const N &, const pubkey &);
    };

}

