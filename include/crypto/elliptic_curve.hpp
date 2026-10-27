// Copyright (c) 2024 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/math/algebra/elliptic_curve.hpp>
#include <crypto/group.hpp>

namespace crypto {

    template <auto curve, math::space::vector<typename decltype (curve)::coordinate, 2> gen, auto order, uint32 cofactor>
    struct elliptic_curve : additive_group<gen, order> {

        using coordinate = decltype (curve)::coordinate;

        using scalar = math::algebra::elliptic_curve<curve>::scalar;

        // a public key
        using affine_point = math::algebra::elliptic_curve<curve>::affine_point;
        using pubkey = affine_point;

        constexpr static const math::space::vector<coordinate, 2> Base = gen;
        constexpr static const scalar Order = order;

        constexpr static uint32 Cofactor = cofactor;

        // a private key or part of a signature.
        struct factor : math::nonzero<math::prime_field<order>> {
            constexpr factor (const scalar &);

            constexpr affine_point operator * (const affine_point &p) const {
                return p * this->Value.Value;
            }

            constexpr affine_point to_public () const {
                return *this * affine_point {Base};
            }
        };

        using secret = factor;

        // NOTE: this is the definition of a tweak, but faster algorithms are possible.
        static affine_point inline tweak (const affine_point &p, const factor &x) {
            return p + to_public (x);
        }

    };

}

