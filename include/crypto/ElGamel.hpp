// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <crypto/hash.hpp>
#include <crypto/group.hpp>

namespace crypto {

    // prime field required. For prime P, order is P - 1. Generator may not
    // generate entire multiplicative group.
    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (decltype (gen)::Modulus == order - 1)
    struct ElGamel : group<gen, order> {

        // it is required that order == P - 1, where P is the order of the prime field.

        using G = group<gen, order>;

        using scalar = G::scalar;
        using element = G::element;

        struct pubkey : element {
            using group<gen, order>::element::element;
        };

        struct secret : scalar {
            pubkey to_public () const {
                return G::exp (gen, *this);
            }

            bool valid () const {
                return scalar::valid () && *this != 0;
            }
        };

        static secret generate (random::source &oo) {
            while (true) {
                secret k;
                oo >> k;
                if (k.valid ()) return k;
            }
        }

        using message = element;

        using encrypted = pair<element, element>;

        // encrypt with a random k
        static encrypted encrypt (const message &m, const pubkey &, random::source &x);

        // encrypt with a function that generates k somehow.
        // it is theoretically possible for the signature to fale with a
        // given k, though very unlikely, so we need to be able to
        // regenerate a new one if we have to.
        static encrypted encrypt (const message &, const pubkey &, function<secret ()>);

        static message decrypt (const encrypted &, const secret &);

        using signature = struct {
            element R;
            scalar S;
        };

        // sign with a random k
        template <size_t size> static signature sign (const hash::digest<size> &, const secret &, random::source &x);

        // sign with a function to generate k.
        template <size_t size> static signature sign (const hash::digest<size> &, const secret &, function<secret ()>);

        template <size_t size> static bool verify (const hash::digest<size> &, const signature &, const pubkey &);
    };

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (decltype (gen)::Modulus == order - 1)
    ElGamel<gen, order>::encrypted inline ElGamel<gen, order>::encrypt (const message &m, const pubkey &y, random::source &oo) {
        return ElGamel::encrypt (m, y, [&oo] () {
            return generate (oo);
        });
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (decltype (gen)::Modulus == order - 1)
    ElGamel<gen, order>::encrypted inline ElGamel<gen, order>::encrypt (const message &m, const pubkey &y, function<secret ()> f) {
        while (true) {
            secret k = f ();
            if (!k.valid () || k == 0) continue;
            return encrypted {exp (gen, k), m * G::exp (y, k)};
        }
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (decltype (gen)::Modulus == order - 1)
    ElGamel<gen, order>::message inline ElGamel<gen, order>::decrypt (const encrypted &c, const secret &z) {
        return c.second / G::exp (c.first, z);
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (decltype (gen)::Modulus == order - 1) template <size_t size>
    ElGamel<gen, order>::signature inline ElGamel<gen, order>::sign (const hash::digest<size> &h, const secret &z, random::source &oo) {
        return ElGamel::sign (h, z, [&oo] () {
            return generate (oo);
        });
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (decltype (gen)::Modulus == order - 1) template <size_t size>
    ElGamel<gen, order>::signature inline ElGamel<gen, order>::sign (const hash::digest<size> &h, const secret &z, function<secret ()> f) {
        while (true) {
            secret k = f ();
            if (!k.valid ()) continue;
            auto kinv = invert_mod (k, order);
            if (!kinv) continue;
            element r = G::exp (gen, k);
            if (r == 0) continue;
            auto ss = scalar (h) - scalar (r) * z;
            if (ss == 0) continue;
            return {r, (ss) * *kinv};
        }
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (decltype (gen)::Modulus == order - 1) template <size_t size>
    bool inline ElGamel<gen, order>::verify (const hash::digest<size> &h, const signature &x, const pubkey &y) {
        return G::exp (gen, scalar (h)) == G::exp (x.R, x.S) * G::exp (y, scalar (x.first));
    }
}

