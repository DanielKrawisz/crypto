// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/function.hpp>
#include <crypto/group.hpp>

namespace crypto {

    template <typename N, auto gen, auto order>
    requires PrimeField<decltype (gen)>
    struct DSA : group<gen, order> {
        struct pubkey : group<gen, order>::element {
            using group<gen, order>::element::element;
        };

        using scalar = group<gen, order>::scalar;
        struct secret : scalar {
            pubkey to_public () const {
                return group<gen, order>::exp (gen, *this);
            }
        };

        static secret generate (random::source &x) {
            return group<gen, order>::generate (x);
        }

        using message = scalar;

        struct signature {
            scalar R;
            scalar S;
        };

        // sign with a random k
        static signature sign (const message &, const secret &, random::source &);

        // sign with a function that generates k somehow.
        static signature sign (const message &, const secret &, function<scalar ()>);

        static bool verify (const message &, const signature &, const pubkey &);
    };

    template <typename N, auto gen, auto order>
    requires PrimeField<decltype (gen)>
    DSA<N, gen, order>::signature DSA<N, gen, order>::sign (const message &m, const secret &k, random::source &x) {
        return sign (m, k, [x] () {
            scalar u;
            while (true) {
                x >> u;
                if (u.valid ()) return u;
            }
        });
    }
}

