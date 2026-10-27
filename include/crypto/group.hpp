// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/math/power.hpp>
#include <data/math/group.hpp>
#include <data/math/number/random.hpp>
#include <data/math.hpp>
#include <crypto/random.hpp>

namespace crypto {

    template <class G>
    concept Group = math::Group<typename G::element> && MultiplicativeNumber<typename G::scalar> && requires (
        const typename G::element &x,
        const typename G::element &y,
        const typename G::scalar &n
    ) {
        { G::mul (x, y) } -> Same<typename G::element>;
        { G::exp (x, n) } -> Same<typename G::element>;
    } && requires (const typename G::scalar &z) {
        { G::generate (z) } -> Same<typename G::element>;
    } && requires (random::source &oo, typename G::scalar &z) {
        { G::random (oo, z) };
    };

    // should be an abelian group but we don't have a concept for that.
    template <auto gen, auto order>
    requires math::Group<decltype (gen)> && MultiplicativeNumber<decltype (order)>
    struct multiplicative_group {
        using element = decltype (gen);
        using scalar = math::number::modular<order>;

        static void random (random::source &oo, scalar &p) {
            p = scalar {math::number::generate_random_below<decltype (order)> (oo, order)};
        }

        static constexpr element mul (const element &x, const element &y) {
            return x * y;
        }

        static constexpr element exp (
            const element &x,
            const scalar &n
        ) {
            return math::binary_accumulate_pow (x, n.Value);
        }

        static constexpr element generate (
            const scalar &n
        ) {
            return exp (gen, n);
        }
    };

    template <auto gen, auto order>
    requires math::Group<decltype (gen)> && MultiplicativeNumber<decltype (order)>
    struct additive_group {
        using element = decltype (gen);
        using scalar = math::number::modular<order>;

        static void random (random::source &oo, scalar &p) {
            p = scalar {math::number::generate_random_below<decltype (order)> (oo, order)};
        }

        static constexpr element exp (
            const element &x,
            const scalar &n
        ) {
            return math::binary_accumulate_times (x, n.Value);
        }

        static constexpr element generate (
            const scalar &n
        ) {
            return exp (gen, n);
        }
    };

    template <typename>
    struct is_prime_field : std::false_type {};

    template <auto P>
    struct is_prime_field<math::prime_field<P>> : std::true_type {};

    template <typename X>
    concept PrimeField = is_prime_field<X>::value;

    // a standard way of transforming a hash into a scalar.
    namespace NIST {

        template <auto order, endian r, size_t s, std::unsigned_integral w>
        math::number::modular<order> bits_to_scalar (const math::uint<r, s, w> &);
    }

    // RFC 9380
}

