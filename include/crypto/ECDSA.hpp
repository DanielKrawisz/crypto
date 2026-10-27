// Copyright (c) 2024 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <crypto/elliptic_curve.hpp>

namespace crypto {

    template <auto curve, auto gen, auto order, uint32 cofactor> struct ECDSA : elliptic_curve<curve, gen, order, cofactor> {
        using factor = elliptic_curve<curve, gen, order, cofactor>::factor;
        using secret = elliptic_curve<curve, gen, order, cofactor>::factor;
        using pubkey = elliptic_curve<curve, gen, order, cofactor>::factor;

        struct signature {
            factor R;
            factor S;
            bool valid () const;
        };

        // this will fail with a very small probability and
        // then you have to try another ephemeral key.
        signature sign (const factor &message, const secret &key, const factor &ephemeral) const;

        bool verify (const factor &message, const signature &x, const pubkey &key) const;

    };

}
