// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/exception.hpp>
#include <data/numbers.hpp>
#include <data/math.hpp>
#include <data/math/algebra/finite_field.hpp>
#include <crypto/random.hpp>
#include <crypto/hash.hpp>

namespace crypto {

    template <typename nat, size_t bits>
    struct Rabin {
        using natural = nat;
        struct pubkey {
            natural N;
        };

        struct secret {
            natural P;
            natural Q;
            pubkey to_public () const {
                return secret {P * Q};
            }
        };

        static natural generate_Blum_prime (random::source &x, size_t size) {
            while (true) {
                natural p = math::number::generate_random_prime<natural> (x, size);
                if (mod (p, 4) == 3) return p;
            }
        }

        static secret generate (random::source &x) {
            constexpr size_t p_size = bits / 2;
            constexpr size_t q_size = even (bits) ? bits / 2 : bits / 2 + 1;

            natural p;
            natural q;

            while (true) {
                // generate two primes
                p = generate_Blum_prime (x, p_size);
                q = generate_Blum_prime (x, q_size);

                natural n = p * q;

                // make sure their product as the right size. It must be bits bits.
                if (bitwidth (n) != bits) continue;

                natural difference = p > q ? p - q : q - p;

                // make sure their difference is big enough.
                // NIST recommendation for RSA:
                if (difference <= N {1} << (bits / 2 - 100)) continue;

                return secret {p, q};
            }
        }

        using message = natural;
        using encrypted = natural;

        static encrypted encrypt (const message &, const pubkey &);
        static message decrypt (const encrypted &, const secret &);
    };

    template <typename nat, size_t bits>
    struct RabinWilliams {
        using natural = nat;
        struct pubkey {
            natural N;
        };

        struct secret {
            natural P;
            natural Q;
            natural C;
            pubkey to_public () const {
                return secret {P * Q};
            }
        };

        static secret generate (random::source &x) {
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
                if (bitwidth (n) != bits) continue;

                N difference = p > q ? p - q : q - p;

                // make sure their difference is big enough.
                // NIST recommendation for RSA:
                if (difference <= N {1} << (bits / 2 - 100)) continue;

                return secret {p, q};
            }
        }

        static natural sign (const natural &, const secret &);
        static bool verify (const natural &, const pubkey &);
    };

}

