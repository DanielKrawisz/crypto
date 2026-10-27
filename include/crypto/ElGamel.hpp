// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <crypto/hash.hpp>
#include <crypto/group.hpp>

namespace crypto {

    // prime field required. For prime P, order is P - 1. Generator may not
    // generate entire multiplicative group.
    // TODO can generalize to elliptic curves.
    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    struct ElGamel : multiplicative_group<gen, order> {

        // it is required that order == P - 1, where P is the order of the prime field.

        using G = multiplicative_group<gen, order>;

        using scalar = G::scalar;
        using element = G::element;

        struct pubkey;
        struct secret;

        using message = element;

        using encrypted = pair<element, element>;

        using digest = scalar;

        struct signature {
            element R;
            scalar S;

            bool operator == (const signature &x) const;
        };

        // encrypt with a random k
        static encrypted encrypt (const message &m, const pubkey &, random::source &x);

        // encrypt with a function that generates k somehow.
        // it is theoretically possible for the signature to fale with a
        // given k, though very unlikely, so we need to be able to
        // regenerate a new one if we have to.
        static encrypted encrypt (const message &, const pubkey &, function<secret ()>);

        static message decrypt (const encrypted &, const secret &);

        // sign with a random k
        static signature sign (const digest &, const secret &, random::source &x);

        // sign with a function to generate k.
        static signature sign (const digest &, const secret &, function<secret ()>);

        static bool verify (const signature &, const digest &, const pubkey &);

        static secret generate_key (random::source &oo);

        struct pubkey : element {
            using element::element;
            pubkey (element &&e) : element {e} {}

            encrypted encrypt (const message &m, random::source &oo);

            encrypted encrypt (const message &m, function<secret ()> &f);

            bool verify (const signature &x, const digest &h);

            bool operator == (const pubkey &y) const {
                return static_cast<const element &> (*this) == static_cast<const element &> (y);
            }
        };

        struct secret : scalar {
            using scalar::scalar;
            pubkey to_public () const;

            bool valid () const;

            message decrypt (const encrypted &c) const;

            signature sign (const digest &h, random::source &oo);
            signature sign (const digest &h, function<secret ()> &f);

            friend random::source &operator >> (random::source &r, secret &k) {
                while (true) {
                    multiplicative_group<gen, order>::random (r, k);
                    // if the scalar we get happens to be zero,
                    // the key is invalid. This is unlikely and
                    // we just try again.
                    if (k.valid ()) return r;
                }
            }

            secret (scalar &&s): scalar {s} {}
        };
    };

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    ElGamel<gen, order>::secret inline ElGamel<gen, order>::generate_key (random::source &oo) {
        secret k;
        oo >> k;
        return k;
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    ElGamel<gen, order>::encrypted inline ElGamel<gen, order>::encrypt (const message &m, const pubkey &y, random::source &oo) {
        return ElGamel::encrypt (m, y, [&oo] () {
            return generate_key (oo);
        });
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    ElGamel<gen, order>::encrypted inline ElGamel<gen, order>::encrypt (const message &m, const pubkey &y, function<secret ()> f) {
        while (true) {
            secret k = f ();
            if (!k.valid () || k == 0) continue;
            return encrypted {G::exp (gen, k), m * G::exp (y, k)};
        }
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    ElGamel<gen, order>::message inline ElGamel<gen, order>::decrypt (const encrypted &c, const secret &z) {
        return c.second / G::exp (c.first, z);
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    ElGamel<gen, order>::signature inline ElGamel<gen, order>::sign (const digest &h, const secret &z, random::source &oo) {
        return ElGamel::sign (h, z, [&oo] () {
            return generate_key (oo);
        });
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    ElGamel<gen, order>::signature inline ElGamel<gen, order>::sign (const digest &h, const secret &z, function<secret ()> f) {
        while (true) {
            secret k = f ();
            if (!k.valid ()) continue;
            auto kinv = invert_mod (k.Value, math::nonzero {order});
            if (!kinv) continue;
            element r = G::exp (gen, k);
            if (r == 0) continue;
            auto ss = h - scalar (r) * z;
            if (ss == 0) continue;
            return {r, ss * scalar {*kinv}};
        }
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    bool inline ElGamel<gen, order>::verify (const signature &x, const digest &h, const pubkey &y) {
        return G::exp (gen, h) == G::exp (x.R, x.S) * G::exp (y, scalar (x.R));
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    bool inline ElGamel<gen, order>::signature::operator == (const signature &x) const {
        return R == x.R && S == x.S;
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    ElGamel<gen, order>::encrypted inline ElGamel<gen, order>::pubkey::encrypt (const message &m, random::source &oo) {
        return ElGamel::encrypt (m, *this, oo);
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    ElGamel<gen, order>::encrypted inline ElGamel<gen, order>::pubkey::encrypt (const message &m, function<secret ()> &f) {
        return ElGamel::encrypt (m, *this, f);
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    bool inline ElGamel<gen, order>::pubkey::verify (const signature &x, const digest &h) {
        return ElGamel::verify (x, h, *this);
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    ElGamel<gen, order>::pubkey inline ElGamel<gen, order>::secret::to_public () const {
        return G::exp (gen, *this);
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    bool inline ElGamel<gen, order>::secret::valid () const {
        return scalar::valid () && *this != 0;
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    ElGamel<gen, order>::message inline ElGamel<gen, order>::secret::decrypt (const encrypted &c) const {
        return ElGamel::decrypt (c, *this);
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    ElGamel<gen, order>::signature inline ElGamel<gen, order>::secret::sign (const digest &h, random::source &oo) {
        return ElGamel::sign (h, *this, oo);
    }

    template <auto gen, auto order>
    requires PrimeField<decltype (gen)> && (order == decltype (gen)::Modulus - 1)
    ElGamel<gen, order>::signature inline ElGamel<gen, order>::secret::sign (const digest &h, function<secret ()> &f) {
        return ElGamel::sign (h, *this, f);
    }
}

