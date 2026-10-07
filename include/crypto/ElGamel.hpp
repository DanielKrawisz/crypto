// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <crypto/group.hpp>

namespace crypto {

    template <typename N, auto gen, auto order>
    struct ElGamel : group<gen, order> {
        struct pubkey : group<gen, order>::element {
            using group<gen, order>::element::element;
        };

        struct secret : group<gen, order>::scalar {
            pubkey to_public () const {
                return group<gen, order>::exp (gen, *this);
            }
        };

        static secret generate (random::source &x) {
            return group<gen, order>::generate (x);
        }

        using message = N;
        using encrypted = N;

        static encrypted encrypt (const message &, const pubkey &);
        static message decrypt (const encrypted &, const secret &);

        using signature = N;

        static signature sign (const message &, const secret &);
        static bool verify (const message &, const signature&, const pubkey &);
    };
}

