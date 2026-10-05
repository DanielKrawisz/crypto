// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/exception.hpp>
#include <data/numbers.hpp>
#include <data/math/number/NTL/prime.hpp>
#include <crypto/random.hpp>
#include <crypto/hash.hpp>

// NIST SP 800-56B Rev. 2, Recommendation for Pair-Wise Key-Establishment Using Integer Factorization Cryptography
// RFC 8017 specifies RSAES-OAEP as the encryption scheme to support for new applications. It combines RSA with an encoding procedure that incorporates randomness and a hash function.

namespace crypto {
/*
    There are several related considerations:

    Both primes must be sufficiently large. Otherwise, factoring \(n\) may be feasible.
    The primes must be distinct. If \(p=q\), then \(n=p^2\), which is easy to factor by taking its square root.
    The primes should not be too close. If \(p\) and \(q\) are exceptionally close, Fermat's factorization method can factor \(n\) efficiently.
    The primes must satisfy the RSA exponent requirements. For the chosen public exponent \(e\), we need \(\gcd(e,\lambda(n))=1\).

    The third point is particularly interesting because it gives us a concrete condition to consider when designing prime generation.
    */

    template <typename N, size_t bits>
    struct RSA {
        struct pubkey {
            N n;
            N e;
        };

        struct secret {
            N p;
            N q;
            N d;
            pubkey to_public () const;
        };

        static secret generate (random::source &);
        static N encrypt (const N &, const pubkey &);
        static N decrypt (const N &, const secret &);
    };

    template <typename N, size_t bits> RSA<N, bits>::secret RSA<N, bits>::generate (random::source &x) {
        constexpr size_t p_size = bits / 2;
        constexpr size_t q_size = even (bits) ? bits / 2 : bits / 2 + 1;

        N p;
        N q;
        N e = 65537; // standard choice.

        while (true) {
            // generate two primes
            p = math::number::generate_random_prime<N> (x, p_size, 100);
            p = math::number::generate_random_prime<N> (x, q_size, 100);

            N n = p * q;

            // make sure their product as the right size. It must be bits bits.
            if (bitwidth (n) != bits) continue;

            N difference = p > q ? p - q : q - p;

            // make sure their difference is big enough.
            // NIST recommendation:
            if (difference <= N {1} << (bits / 2 - 100)) continue;

            N carmichael = LCM (p - 1, q - 1);

            maybe<N> d = invert_mod (e, carmichael);

            if (d) return secret {p, q, *d};
        }
    }

    template <typename N, size_t bits>
    RSA<N, bits>::pubkey RSA<N, bits>::secret::to_public () const {

        N carmichael = LCM (p - 1, q - 1);

        maybe<N> e = invert_mod (e, carmichael);

        if (!e) throw exception {} << "invalid scecret key";

        return pubkey {p * q, *e};

    }

}

