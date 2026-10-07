// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/exception.hpp>
#include <data/numbers.hpp>
#include <data/math/number/NTL/random.hpp>
#include <data/math/power.hpp>
#include <crypto/random.hpp>
#include <crypto/hash.hpp>

// NIST SP 800-56B Rev. 2, Recommendation for Pair-Wise Key-Establishment Using Integer Factorization Cryptography
// RFC 8017 specifies RSAES-OAEP as the encryption scheme to support for new applications. It combines RSA with an encoding procedure that incorporates randomness and a hash function.

namespace crypto {


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

        using message = N;
        using encrypted = N;

        static secret generate (random::source &, N e = 65537);
        static encrypted encrypt (const message &, const pubkey &);
        static message decrypt (const encrypted &, const secret &);
    };

    template struct RSA<N, 1024>;
    template struct RSA<N, 2048>;
    template struct RSA<N, 3072>;
    template struct RSA<N, 4096>;

    template <typename N, size_t bits> RSA<N, bits>::secret RSA<N, bits>::generate (random::source &x, N e) {
        constexpr size_t p_size = bits / 2 + 1;
        constexpr size_t q_size = even (bits) ? bits / 2 : bits / 2 + 1;

        N p;
        N q;

        while (true) {
            // generate two primes
            p = math::number::generate_random_prime<N> (x, p_size);
            q = math::number::generate_random_prime<N> (x, q_size);

            N n = p * q;

            // make sure their product as the right size. There is approximately a 3/7 chance that it is too big.
            if (bit_width (n) != bits) continue;

            N difference = p > q ? p - q : q - p;

            // make sure their difference is big enough.
            // NIST recommendation:
            if (difference <= N {1} << (bits / 2 - 100)) continue;

            N carmichael = LCM (p - 1, q - 1);

            maybe<N> d = invert_mod (e, math::nonzero {carmichael});

            if (d) return secret {p, q, *d};
        }
    }

    template <typename N, size_t bits>
    RSA<N, bits>::pubkey RSA<N, bits>::secret::to_public () const {

        N carmichael = LCM (p - 1, q - 1);

        maybe<N> e = invert_mod (d, math::nonzero {carmichael});

        if (!e) throw exception {} << "invalid scecret key";

        return pubkey {p * q, *e};

    }

    template <typename N, size_t bits>
    RSA<N, bits>::encrypted inline RSA<N, bits>::encrypt (const message &m, const pubkey &pk) {
        return pow_mod (m, pk.e, math::nonzero {pk.n});
    }

    // TODO we can use the chinese remainder theorem to optimize this.
    template <typename N, size_t bits>
    RSA<N, bits>::message inline RSA<N, bits>::decrypt (const encrypted &c, const secret &sk) {
        return pow_mod (c, sk.d, math::nonzero {sk.p * sk.q});
    }

}

