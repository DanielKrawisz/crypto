// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <crypto/group.hpp>

namespace crypto {

    template <typename N, auto gen, auto order>
    requires PrimeField<decltype (gen)>
    struct DSA : group<gen, order> {
        struct pubkey : group<gen, order>::element {};

        struct secret : group<gen, order>::scalar {
            pubkey to_public () const {
                return group<gen, order>::exp (gen, *this);
            }
        };

        static secret generate (random::source &);
        static N sign (const N &, const secret &);
        static bool verify (const N &, const pubkey &);
    };
}

