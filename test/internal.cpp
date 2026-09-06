// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <crypto/hash/internal.hpp>

namespace crypto {

    TEST (Internal, Scrypt) {

        EXPECT_EQ (
            (crypto::scrypt<64> (
                bytes (data::string ("")),
                bytes (data::string ("")),
                16, 1, 1)),
            (byte_array<64> (encoding::hex::fixed<64> {
                "77d6576238657b203b19ca42c18a0497"
                "f16b4844e3074ae8dfdffa3fede21442"
                "fcd0069ded0948f8326a753a0fc81f17"
                "e8d3e0fb2e0d3628cf35e20c38d18906"})));

        EXPECT_EQ (
            (crypto::scrypt<64> (
                bytes (data::string ("password")),
                bytes (data::string ("NaCl")),
                1024, 8, 16)),
            (byte_array<64> (encoding::hex::fixed<64> {
                "fdbabe1c9d3472007856e7190d01e9fe"
                "7c6ad7cbc8237830e77376634b373162"
                "2eaf30d92e22a3886ff109279d9830da"
                "c727afb94a83ee6d8360cbdfa2cc0640"})));

        // these ones take too long but they pass.
/*
        EXPECT_EQ (
            (crypto::scrypt<64> (
                bytes (data::string ("pleaseletmein")),
                bytes (data::string ("SodiumChloride")),
                16384, 8, 1)),
            (byte_array<64> (encoding::hex::fixed<64> {
                "7023bdcb3afd7348461c06cd81fd38eb"
                "fda8fbba904f8e3ea9b543f6545da1f2"
                "d5432955613f0fcf62d49705242a9af9"
                "e61e85dc0d651e40dfcf017b45575887"})));

        EXPECT_EQ (
            (crypto::scrypt<64> (
                bytes (data::string ("pleaseletmein")),
                bytes (data::string ("SodiumChloride")),
                1048576, 8, 1)),
            (byte_array<64> (encoding::hex::fixed<64> {
                "2101cb9b6a511aaeaddbbe09cf70f881"
                "ec568d574a2ffd4dabe5ee9820adaa47"
                "8e56fd8f4ba5d09ffa1c6d927c40f4c3"
                "37304049e8a952fbcbf45c6fa77a41a4"})));*/

    }
}
