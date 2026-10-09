// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/function.hpp>
#include <crypto/group.hpp>

namespace crypto {

    // order is required to be a prime Q.
    // Thus, the space of keys only covers one prime-order subgroup of
    // the multiplicative group mod P.
    // it is optimal to use a so-called "safe" prime.
    template <auto gen, auto order>
    requires PrimeField<decltype (gen)>
    struct DSA : group<gen, order> {

        using G = group<gen, order>;

        using scalar = math::prime_field<order, decltype (std::declval<group<gen, order>> ().Value)>;
        using element = G::element;

        struct pubkey : element {
            using element::element;
        };

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
        template <size_t size>
        static signature sign (const hash::digest<size> &, const secret &, random::source &);

        // sign with a function that generates k somehow.
        // it is theoretically possible for the signature to fale with a
        // given k, though very unlikely, so we need to be able to
        // regenerate a new one if we have to.
        template <size_t size>
        static signature sign (const hash::digest<size> &, const secret &, function<secret ()>);

        template <size_t size>
        static bool verify (const hash::digest<size> &, const signature &, const pubkey &);
    };

    template <auto gen, auto order> requires PrimeField<decltype (gen)> template <size_t size>
    DSA<gen, order>::signature DSA<gen, order>::sign (const hash::digest<size> &m, const secret &k, random::source &oo) {
        return sign (m, k, [oo] () {
            generate (oo);
        });
    }

    template <auto gen, auto order> requires PrimeField<decltype (gen)> template <size_t size>
    DSA<gen, order>::signature DSA<gen, order>::sign (const hash::digest<size> &h, const secret &z, function<secret ()> f) {
        while (true) {
            auto k = f ();
            if (!k.valid ()) continue;
            scalar r = scalar (G::exp (gen, k));
            if (r == 0) continue;
            auto kinv = ~k; // this will always exist
            scalar s = kinv * (scalar (h) - z * r);
            if (s == 0) continue;
            return {r, s};
        }
    }

    template <auto gen, auto order> requires PrimeField<decltype (gen)> template <size_t size>
    bool DSA<gen, order>::verify (const hash::digest<size> &h, const signature &x, const pubkey &y) {
        auto w = ~x.S;
        return x.R == G::exp (gen, scalar (h) * w) * G::exp (gen, x.R * w);
    }
}

