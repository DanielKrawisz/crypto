// Copyright (c) 2018-2022 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <data/random.hpp>
#include <data/function.hpp>

namespace crypto {
    using namespace data;
    
    enum class security : byte {
        none = 0,
        weak = 1,
        depricated = 2,
        modern = 3,
        encrypted = 4,
        integrity = 8,
        authenticated = 16
    };
    
    // keypair is an assertion that to_public
    // is a non-invertable function between
    // sk and pk. 
    template <typename sk, typename pk> 
    concept Keypair = requires (sk s) {
        { to_public (s) } -> Same<pk>;
    };

    template <typename ks>
    concept KeySystem = Keypair<typename ks::secret, typename ks::pubkey> &&
    requires (random::source &r) {
        { ks::generate (r) } -> Same<typename ks::secret>;
    };

    template <typename es>
    concept EncryptionScheme = KeySystem<es> &&
    requires (typename es::message m, typename es::pubkey k) {
        { es::encrypt (m, k) } -> Same<typename es::encrypted>;
    } && requires (typename es::encrypted m, typename es::secret k) {
        { es::decrypt (m, k) } -> Same<typename es::message>;
    };
    
    template <typename ss>
    concept SignatureScheme = KeySystem<ss> &&
    requires (typename ss::message m, typename ss::pubkey k) {
        { ss::sign (m, k) } -> Same<typename ss::signature>;
    } && requires (typename ss::message m, typename ss::signature x, typename ss::pubkey k) {
        { ss::verify (m, x, k) } -> Same<bool>;
    };
    
}
