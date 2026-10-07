// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <crypto/random.hpp>
#include <crypto/group.hpp>

// A Diffie-Hellman group allows two parties to establish a shared secret
// over a public channel, using private values that remain secret.
//
// The group has an element g, called the generator or base. Each party
// independently generates a private scalar x and computes its public key
// as g^x. After exchanging public keys, each party raises the other
// party's public key to its own private key. Both obtain the same
// shared secret:
//
//     A = g^a
//     B = g^b
//     K = B^a = A^b = g^(ab)
//
// The security of the protocol relies on the difficulty of recovering
// the shared secret from the public keys and the public parameters.
//
// G::scalar is the type of private keys, and G::element is the type
// of group elements, including public keys and shared secrets.
//
// G::generate uses a cryptographically secure random source to generate
// a private key suitable for the group.
//
// G::power raises a group element to a scalar exponent.
//
// Implementations must ensure that generated private keys are valid
// for their group and that public keys received from other parties
// are validated before being used to derive a shared secret.

namespace crypto {

    template <typename G>
    concept DiffieHellman =
    requires (random::source &x) {
        // generate a random private scalar
        { G::generate (x) } -> Same<typename G::scalar>;
    } && requires (
        const typename G::element &g,
        const typename G::scalar &x
    ) {
        // generate the public key from the private scalar
        // if g is the generator, or generate the shared secret
        // from the other party's public key if g is the public key..
        { G::exp (g, x) } -> std::same_as<typename G::element>;
    };

    template <typename N, auto gen, auto order>
    struct diffie_hellman : group<gen, order> {};

    // standard primes for prime field diffie helman.
    namespace rfc3526 {
        // modp5
        // modp14
        // modp15
        // modp16
        // modp17
        // modp18
    }

    namespace rfc7919 {
        // ffdhe2048
        // ffdhe3072
        // ffdhe4096
        // ffdhe6144
        // ffdhe8192

    }
}
