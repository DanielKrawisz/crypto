// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/exception.hpp>
#include <data/numbers.hpp>
#include <data/math.hpp>
#include <data/math/algebra/finite_field.hpp>
#include <data/set.hpp>
#include <crypto/random.hpp>
#include <crypto/hash.hpp>

namespace crypto {

    template <typename nat, size_t bits>
    struct Rabin {
        using natural = nat;

        struct pubkey;
        struct secret;

        using message = natural;
        using encrypted = natural;

        static encrypted encrypt (const message &, const pubkey &);
        static set<message> decrypt (const encrypted &, const secret &);

        struct pubkey {
            math::nonzero<natural> N;

            bool operator == (const pubkey &p) const {
                return N == p.N;
            }

            encrypted encrypt (const message &m) const {
                return Rabin::encrypt (m, *this);
            }

            friend std::ostream &operator << (std::ostream &o, const pubkey &p) {
                return o << p.N;
            }
        };

        struct secret {
            math::number::prime<natural> P;
            math::number::prime<natural> Q;

            secret (): P {}, Q {} {}
            secret (const math::number::prime<natural> &p, const math::number::prime<natural> &q): P {p}, Q {q} {}

            pubkey to_public () const {
                if (!data::valid (N)) N = math::nonzero {P.Value * Q.Value};
                return pubkey {N};
            }

            bool operator == (const secret &z) const {
                return P == z.P && Q == z.Q;
            }

            bool valid () const;

            set<message> decrypt (const encrypted &c) const {
                natural mp = pow_mod (c, (P.Value + 1u) / 4u, P);
                natural mq = pow_mod (c, (Q.Value + 1u) / 4u, Q);
                precalculate ();
                natural pp = mp * Q.Value * *A;
                natural qp = mq * P.Value * *B;
                natural pn = negate_mod (pp, N);
                natural qn = negate_mod (qp, N);

                return set<message> {
                    mod (pp + qp, N),
                    mod (pp + qn, N),
                    mod (pn + qp, N),
                    mod (pn + qn, N)};
            }

            friend random::source &operator >> (random::source &oo, secret &k) {
                constexpr size_t p_size = bits / 2;
                constexpr size_t q_size = even (bits) ? bits / 2 : bits / 2 + 1;
                while (true) {
                    // generate two primes
                    k.P = generate_Blum_prime (oo, p_size);
                    k.Q = generate_Blum_prime (oo, q_size);

                    if (k.valid ()) return oo;
                }
            }

            friend std::ostream &operator << (std::ostream &o, const secret &z) {
                return o << "{" << z.P << ", " << z.Q << "}";
            }

        private:
            mutable math::nonzero<natural> N {}; // P * Q
            mutable maybe<natural> A {};     // inverse of Q mod P
            mutable maybe<natural> B {};     // inverse of P mod Q
            void precalculate () const {
                if (!data::valid (N)) N = math::nonzero {P.Value * Q.Value};
                if (!A) A = *invert_mod (Q.Value, P);
                if (!B) B = *invert_mod (P.Value, Q);
            }
        };

        static math::number::prime<natural> generate_Blum_prime (random::source &oo, size_t size);

        static secret generate_key (random::source &x);
    };

    template <typename nat, size_t bits>
    struct RabinWilliams {
        using natural = nat;

        struct pubkey;
        struct secret;

        using signature = natural;

        template <size_t size> static signature sign (const hash::digest<size> &, const secret &);
        template <size_t size> static bool verify (const hash::digest<size> &, const pubkey &);

        struct pubkey {
            natural N;

            bool operator == (const pubkey &p) const {
                return N == p.N;
            }
        };

        struct secret {
            natural P;
            natural Q;
            natural C;

            pubkey to_public () const;
            bool operator == (const secret &) const;
        };

        static secret generate_key (random::source &x);
    };

    template <typename nat, size_t bits>
    math::number::prime<nat> Rabin<nat, bits>::generate_Blum_prime (random::source &oo, size_t size) {
        while (true) {
            auto p = math::number::generate_random_prime<natural> (oo, size);
            if (p.Value % 4 == 3) return p;
        }
    }

    template <typename nat, size_t bits>
    Rabin<nat, bits>::secret Rabin<nat, bits>::generate_key (random::source &x) {
        secret k;
        x >> k;
        return k;
    }

    template <typename nat, size_t bits>
    bool Rabin<nat, bits>::secret::valid () const {
        if (!P.valid () || !Q.valid ()) return false;

        if (P.Value % 4 != 3 || Q.Value % 4 != 3) return false;

        natural n = P * Q;

        // make sure their product as the right size. It must be bits bits.
        if (bit_width (n) != bits) return false;

        natural difference = P > Q ? P.Value - Q.Value : Q.Value - P.Value;


        // make sure their difference is big enough.
        // we allow for toy models that have few bits and are only required
        // to be distinct, rather than to differ by a sufficient amount.
        natural min_difference = 0;

        // NIST recommendation:
        if constexpr (bits > 200) min_difference = natural {1} << (bits / 2 - 100);

        return difference > min_difference;
    }

    template <typename nat, size_t bits>
    Rabin<nat, bits>::encrypted inline Rabin<nat, bits>::encrypt (const message &m, const pubkey &y) {
        return square_mod (m, y.N);
    }

    template <typename nat, size_t bits>
    set<typename Rabin<nat, bits>::message> inline Rabin<nat, bits>::decrypt (const encrypted &c, const secret &y) {
        return y.decrypt (c);
    }

    template <typename nat, size_t bits>
    RabinWilliams<nat, bits>::secret RabinWilliams<nat, bits>::generate_key (random::source &x) {
        constexpr size_t p_size = bits / 2;
        constexpr size_t q_size = even (bits) ? bits / 2 : bits / 2 + 1;

        natural p;
        natural q;

        while (true) {
            // generate two primes
            p = math::number::generate_random_prime<N> (x, p_size);
            if (mod (p, 8) != 3) continue;

            q = math::number::generate_random_prime<N> (x, q_size);
            if (mod (q, 8) != 7) continue;

            natural n = p * q;

            // make sure their product as the right size. It must be bits bits.
            if (bit_width (n) != bits) continue;

            natural difference = p > q ? p - q : q - p;

            // make sure their difference is big enough.
            // NIST recommendation for RSA:
            if (difference <= natural {1} << (bits / 2u - 100u)) continue;

            return secret {p, q};
        }
    }

}

