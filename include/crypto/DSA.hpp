// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/function.hpp>
#include <crypto/hash.hpp>
#include <crypto/group.hpp>

namespace crypto {

    // order is required to be a prime Q.
    // Thus, the space of keys only covers one prime-order subgroup of
    // the multiplicative group mod P.
    // it is optimal to use a so-called "safe" prime.
    template <auto gen, auto order> requires PrimeField<decltype (gen)>
    // TODO we can generalize to elliptic curves, although you should actually use ECDSA if you want to use elliptic curves.
    struct DSA : multiplicative_group<gen, order> {

        using G = multiplicative_group<gen, order>;

        struct scalar : math::prime_field<order, decltype (gen.Value)> {
            using math::prime_field<order, decltype (gen.Value)>::prime_field;

            template <endian r, size_t size, std::unsigned_integral word>
            scalar (const math::uint<r, size, word> &);
        };

        using element = G::element;

        struct pubkey;
        struct secret;

        using message = scalar;

        using digest = scalar;

        struct signature {
            scalar R;
            scalar S;
            bool operator == (const signature &x) const;
        };

        // sign with a random k
        static signature sign (const digest &, const secret &, random::source &);

        // sign with a function that generates k somehow.
        // it is theoretically possible for the signature to fale with a
        // given k, though very unlikely, so we need to be able to
        // regenerate a new one if we have to.
        static signature sign (const digest &, const secret &, function<secret ()>);

        static bool verify (const signature &, const digest &, const pubkey &);

        struct pubkey : element {
            using element::element;
            pubkey (element &&e): element {e} {}
            pubkey (const element &e) : element {e} {}
            bool verify (const signature &x, const digest &h) const;

            bool operator == (const pubkey &y) const {
                return static_cast<const element &> (*this) == static_cast<const element &> (y);
            }
        };

        struct secret : scalar {
            pubkey to_public () const;

            signature sign (const digest &h, random::source &oo) const;
            signature sign (const digest &h, function<secret ()> f) const;

            friend random::source &operator >> (random::source &oo, secret &k) {
                while (true) {
                    multiplicative_group<gen, order>::random (oo, k);
                    if (k.valid ()) return oo;
                }
            }
        };

        static secret generate_key (random::source &oo) {
            secret k {};
            oo >> k;
            return k;
        }
    };

    template <auto gen, auto order> requires PrimeField<decltype (gen)>
    DSA<gen, order>::signature DSA<gen, order>::sign (const digest &h, const secret &k, random::source &oo) {
        return sign (h, k, [&oo] () {
            return generate_key (oo);
        });
    }

    template <auto gen, auto order> requires PrimeField<decltype (gen)>
    DSA<gen, order>::signature DSA<gen, order>::sign (const digest &h, const secret &z, function<secret ()> f) {
        while (true) {
            auto k = f ();
            if (!k.valid ()) continue;
            scalar r = scalar (G::exp (gen, k));
            if (r == 0) continue;
            auto kinv = ~k; // this will always exist
            scalar s = kinv * (h + z * r);
            if (s == 0) continue;
            return {r, s};
        }
    }

    template <auto gen, auto order> requires PrimeField<decltype (gen)>
    bool DSA<gen, order>::verify (const signature &x, const digest &h, const pubkey &y) {
        if (x.R == 0 || x.R >= order) return false;
        if (x.S == 0 || x.S >= order) return false;

        auto w = ~x.S;
        auto u1 = h * w;
        auto u2 = x.R * w;

        return scalar (G::exp (gen, u1) * G::exp (y, u2)) == x.R;
    }

    template <auto gen, auto order> requires PrimeField<decltype (gen)>
    bool inline DSA<gen, order>::signature::operator == (const signature &x) const {
        return R == x.R && S == x.S;
    }


    template <auto gen, auto order> requires PrimeField<decltype (gen)>
    bool inline DSA<gen, order>::pubkey::verify (const signature &x, const digest &h) const {
        return DSA::verify (x, h, *this);
    }

    template <auto gen, auto order> requires PrimeField<decltype (gen)>
    DSA<gen, order>::pubkey inline DSA<gen, order>::secret::to_public () const {
        return pubkey {multiplicative_group<gen, order>::exp (gen, *this)};
    }

    template <auto gen, auto order> requires PrimeField<decltype (gen)>
    DSA<gen, order>::signature inline DSA<gen, order>::secret::sign (const digest &h, random::source &oo) const {
        return DSA::sign (h, *this, oo);
    }

    template <auto gen, auto order> requires PrimeField<decltype (gen)>
    DSA<gen, order>::signature inline DSA<gen, order>::secret::sign (const digest &h, function<secret ()> f) const {
        return DSA::sign (h, *this, f);
    }

}

