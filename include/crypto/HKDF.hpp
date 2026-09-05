// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTO_HKDF
#define CRYPTO_HKDF

#include <crypto/hash.hpp>
#include <crypto/cipher.hpp>
#include <crypto/MAC/HMAC.hpp>

namespace crypto {

    template <hash::Engine H>
    struct HKDF : reader<byte> {
        using PRK = cipher::symmetric_key<H::DigestSize>;

        // Extract pseudorandom key material from input keying material.
        template <size_t key_size>
        static PRK extract (byte_slice ikm, const cipher::symmetric_key<key_size> &salt) {
            return HMAC<H> (salt, ikm);
        }

        static const cipher::symmetric_key<H::DigestSize> &default_salt () {
            static cipher::symmetric_key<H::DigestSize> DefaultSalt {};
            return DefaultSalt;
        };

        // use default salt.
        static PRK extract (byte_slice ikm) {
            return extract<H::DigestSize> (ikm, default_salt ());
        }

        static bytestring<byte> expand (PRK prk, byte_slice info, std::size_t length);

        template <size_t key_size>
        HKDF (byte_slice ikm,
              const cipher::symmetric_key<key_size> &salt,
              byte_slice info,
              std::size_t length): HKDF {extract (ikm, salt), info, length} {}

        HKDF (byte_slice ikm,
              byte_slice info,
              std::size_t length): HKDF {extract (ikm), info, length} {}

        HKDF (PRK prk, byte_slice info, std::size_t length):
            Result {expand (prk, info, length)},
            It {Result.begin (), Result.end ()} {}

        bytestring<byte> Result;
        iterator_reader<bytestring<byte>::iterator> It;

        void read (byte *b, size_t size) final override {
            It.read (b, size);
        }

        void skip (size_t size) final override {
            It.skip (size);
        }

        // not copyable
        HKDF (const HKDF &) = delete;
        HKDF &operator = (const HKDF &) = delete;
        HKDF (HKDF &&) = delete;
        HKDF &operator = (HKDF &&) = delete;

    };

    template <hash::Engine H>
    bytestring<byte> HKDF<H>::expand (
        PRK prk,
        byte_slice info,
        std::size_t length
    ) {
        if (length > 255 * H::DigestSize)
            throw std::invalid_argument ("HKDF output too large");

        bytestring<byte> result; {
            lazy_bytes_writer writer {result};

            bytestring<byte> previous;
            std::size_t written = 0;

            for (byte counter = 1; written < length; ++counter) {
                bytestring<byte> input;
                {
                    lazy_bytes_writer input_writer {input};

                    input_writer << previous << info << counter;
                }

                previous = HMAC<H> (prk, input);

                std::size_t n = std::min (
                    H::DigestSize,
                    length - written);

                writer << byte_slice {
                    previous.data (),
                    n
                };

                written += n;
            }
        }

        return result;
    }

}

#endif

