// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/exception.hpp>
#include <data/math/number/NTL/random.hpp>
#include <data/numbers.hpp>
#include <data/math/number/factor.hpp>
#include <data/math/number/extended_euclidian.hpp>
#include <crypto/random.hpp>
#include <crypto/hash.hpp>

// NIST SP 800-56B Rev. 2, Recommendation for Pair-Wise Key-Establishment Using Integer Factorization Cryptography
// RFC 8017 specifies RSAES-OAEP as the encryption scheme to support for new applications. It combines RSA with an encoding procedure that incorporates randomness and a hash function.

// this is bare RSA, so not yet practical in a real system.

namespace crypto {

    template <Number num, size_t bits>
    struct RSA {
        using natural = num;

        using message = natural;
        using encrypted = natural;

        struct secret;
        struct pubkey;

        static secret generate (random::source &, const natural &e = 65537);

        static encrypted encrypt (const message &, const pubkey &);
        static message decrypt (const encrypted &, const secret &);

        struct pubkey {
            natural N;
            natural E;

            bool operator == (const pubkey &y) const {
                return N == y.N && E == y.E;
            }

            encrypted encrypt (const message &e) const {
                return RSA::encrypt (e, *this);
            }

            friend std::ostream &operator << (std::ostream &o, const pubkey &p) {
                return o << "{" << p.N << ", " << p.E << "}";
            }

        };

        struct secret {
            math::number::prime<natural> P;
            math::number::prime<natural> Q;
            natural D;

            secret (const math::number::prime<natural> &p, const math::number::prime<natural> &q, const natural &d);
            pubkey to_public () const;
            bool valid () const;

            bool operator == (const secret &z) const {
                return P == z.P && Q == z.Q && D == z.D;
            }

            message decrypt (const encrypted &c) const {
                return RSA::decrypt (c, *this);
            }

            friend std::ostream &operator << (std::ostream &o, const secret &z) {
                return o << "{" << z.P << ", " << z.Q << ", " << z.D << "}";
            }

        private:
            natural DP;
            natural DQ;
            natural Q_;
            friend message RSA::decrypt (const encrypted &, const secret &);
        };
    };

    template struct RSA<N, 1024>;
    template struct RSA<N, 2048>;
    template struct RSA<N, 3072>;
    template struct RSA<N, 4096>;

    template <Number num, size_t bits> bool RSA<num, bits>::secret::valid () const {
        if (!P.valid () || !Q.valid ()) return false;

        natural n = P * Q;

        // make sure their product as the right size. There is approximately a 3/7 chance that it is too big.
        if (bit_width (n) != bits) return false;

        natural difference = P.Value > Q.Value ? P.Value - Q.Value : Q.Value - P.Value;

        // make sure their difference is big enough.
        // we allow for toy models that have few bits and are only required
        // to be distinct, rather than to differ by a sufficient amount.
        natural min_difference = 0;

        // NIST recommendation:
        if constexpr (bits > 200) min_difference = natural {1} << (bits / 2 - 100);

        if (difference <= min_difference) return false;

        return bool (invert_mod (D, math::nonzero {LCM (P.Value - 1u, Q.Value - 1u)}));
    }

    template <Number num, size_t bits> RSA<num, bits>::secret RSA<num, bits>::generate (random::source &x, const natural &e) {
        constexpr size_t p_size = bits / 2 + 1;
        constexpr size_t q_size = even (bits) ? bits / 2 : bits / 2 + 1;

        natural p;
        natural q;

        while (true) {
            // generate two primes
            math::number::prime<natural> p = math::number::generate_random_prime<natural> (x, p_size);
            math::number::prime<natural> q = math::number::generate_random_prime<natural> (x, q_size);

            // make sure their product as the right size. There is approximately a 3/7 chance that it is too big.
            natural n = p * q;
            if (bit_width (n) != bits) continue;

            natural difference = p > q ? p.Value - q.Value : q.Value - p.Value;

            // make sure their difference is big enough.
            // we allow for toy models that have few bits and are only required
            // to be distinct, rather than to differ by a sufficient amount.
            natural min_difference = 0;

            // NIST recommendation:
            if constexpr (bits > 200) min_difference = natural {1} << (bits / 2 - 100);

            if (difference <= min_difference) continue;

            natural carmichael = LCM (p.Value - 1, q.Value - 1);

            maybe<natural> d = invert_mod (e, math::nonzero {carmichael});

            if (d) return secret {p, q, *d};
        }
    }

    template <Number num, size_t bits>
    inline RSA<num, bits>::secret::secret (const math::number::prime<natural> &p, const math::number::prime<natural> &q, const natural &d): P {p}, Q {q}, D {d},
    DP {mod (d, math::nonzero {p.Value - 1u})}, DQ {mod (d, math::nonzero {q.Value - 1u})}, Q_{*invert_mod (q.Value, p)} {}

    template <Number num, size_t bits>
    RSA<num, bits>::pubkey RSA<num, bits>::secret::to_public () const {

        natural carmichael = LCM (P.Value - 1, Q.Value - 1);

        maybe<natural> e = invert_mod (D, math::nonzero {carmichael});

        if (!e) throw exception {} << "invalid scecret key";

        return pubkey {P * Q, *e};

    }

    template <Number num, size_t bits>
    RSA<num, bits>::encrypted inline RSA<num, bits>::encrypt (const message &m, const pubkey &pk) {
        return pow_mod (m, pk.E, math::nonzero {pk.N});
    }

    // TODO we can use the chinese remainder theorem to optimize this.
    template <Number num, size_t bits>
    RSA<num, bits>::message RSA<num, bits>::decrypt (const encrypted &c, const secret &sk) {
        auto mp = pow_mod (c, sk.DP, sk.P);
        auto mq = pow_mod (c, sk.DQ, sk.Q);

        // this cannot be zero because P and Q are distinct primes.
        return mod (mq + sk.Q.Value * sk.Q_ * (mp - mq), sk.P);

        // the result ought to be the same as this.
        // return pow_mod (c, sk.D, math::nonzero {natural (sk.P * sk.Q)});
    }

}

