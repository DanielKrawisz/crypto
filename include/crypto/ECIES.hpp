// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/function.hpp>
#include <crypto/cipher.hpp>
#include <crypto/hash.hpp>
#include <crypto/MAC.hpp>
#include <crypto/elliptic_curve.hpp>

namespace crypto::ECIES {

    template <typename curve, hash::Engine hash, size_t key_size, MAC::Engine<key_size> mac, typename cipher> struct base {

        using point = typename curve::point;
        using seed = bytes;

        using key = typename cipher::symmetric_key<key_size>;

        struct keys {
            key Encrypt;
            key MAC;
        };

        using derive = function<keys (const point &)>;

        base (derive);

        using secret = typename curve::secret;
        using pubkey = typename curve::pubkey;

        bytes encrypt (const pubkey &to, const secret &from, const bytes &msg);

        bytes decryt (const secret &to, const pubkey &from, const bytes &enc);

    };





}
