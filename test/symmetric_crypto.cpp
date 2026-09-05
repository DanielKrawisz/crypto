// Copyright (c) 2024 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <data/random.hpp>
#include <data/tuple.hpp>
#include <data/list.hpp>

#include <crypto/hash.hpp>
#include <crypto/block.hpp>
#include <crypto/MAC/NIST.hpp>
#include <crypto/stream/cryptopp.hpp>
#include <crypto/block/cryptopp.hpp>
#include <crypto/NIST_DRBG.hpp>

namespace crypto {

    // we don't test that things actually work, merely that all the functions are implemented and no errors are thrown.

    template <size_t... X> struct keys : tuple<cipher::symmetric_key<X>...> {
        using parent = tuple<cipher::symmetric_key<X>...>;
        using typename parent::tuple;
    };

    template <size_t size> cipher::symmetric_key<size> read_key (const std::string &x) {
        cipher::symmetric_key<size> k;
        boost::algorithm::unhex (x.begin (), x.end (), k.begin ());
        return k;
    }

    // here are the keys we will try using.
    // if a particular key is not supported for a block cipher, it will be skipped.
    keys<8, 16, 20, 24, 28, 32, 40, 48, 56> test_keys {
        read_key<8>  ("0123456789abcdef"),
        read_key<16> ("0123456789abcdef0369cf258be147ad"),
        read_key<20> ("0123456789abcdef0369cf258be147ad05af49e3"),
        read_key<24> ("0123456789abcdef0369cf258be147ad05af49e38d27c16b"),
        read_key<28> ("0123456789abcdef0369cf258be147ad05af49e38d27c16b07e5c3a1"),
        read_key<32> ("0123456789abcdef0369cf258be147ad05af49e38d27c16b07e5c3a18f6d4b29"),
        read_key<40> ("0123456789abcdef0369cf258be147ad05af49e38d27c16b07e5c3a18f6d4b29092b4d6f81a3c5e7"),
        read_key<48> ("0123456789abcdef0369cf258be147ad05af49e38d27c16b07e5c3a18f6d4b29092b4d6f81a3c5e70b61c72d83e94fa5"),
        read_key<56> ("0123456789abcdef0369cf258be147ad05af49e38d27c16b07e5c3a18f6d4b29092b4d6f81a3c5e70b61c72d83e94fa50da741eb852fc963")};

    // first test is MACs. We have HMAC and CMAC.
    const char *MACMessage = "This is a message that will be hashed using a secret key to produce a MAC. Thank you.";
    const char *MACAltered = "This is x message thxt will be hxshed using x secret key to produce x MAC. Thxnk you.";

    template <typename w, size_t key_size> requires MAC::Writer<w, key_size>
    void test_MAC (const char *message1, const char *message2) {
        typename w::digest D1;
        typename w::digest D2;
        {
            w ww {D1, std::get<cipher::symmetric_key<key_size>> (test_keys)};
            w wv {D2, std::get<cipher::symmetric_key<key_size>> (test_keys)};
            ww << bytes (string {message1});
            wv << bytes (string {message2});
        }
        EXPECT_NE (D1, D2);
    }

    template <typename w> struct test_MACs {
        test_MACs (const char *message, const char *altered) {
            test_MAC<w, 16> (message, altered);
            test_MAC<w, 20> (message, altered);
            test_MAC<w, 28> (message, altered);
            test_MAC<w, 32> (message, altered);
        }
    };

    template <hash::Engine e, size_t key_size> void HMAC_test_case (
        const bytes &k,
        const string &msg,
        const hash::digest<e::DigestSize> &result) {
        bytes msg_bytes (msg);
        cipher::symmetric_key<key_size> key;
        std::copy (k.begin (), k.end (), key.begin ());
        auto got = HMAC<e> (key, msg_bytes);
        EXPECT_EQ (got, result) << "HMAC key " << k << " and msg " << msg << "; expected " << result << "; got " << got;
    }

    // test for all hash functions we have
    TEST (MAC, HMAC) {

        // test that the mac is different when a message is altered for various parameters.
        test_MACs<MAC::writer<MAC::HMAC<hash::SHA1>>> {MACMessage, MACAltered};
        test_MACs<MAC::writer<MAC::HMAC<hash::RIPEMD<16>>>> {MACMessage, MACAltered};
        test_MACs<MAC::writer<MAC::HMAC<hash::RIPEMD<20>>>> {MACMessage, MACAltered};
        test_MACs<MAC::writer<MAC::HMAC<hash::RIPEMD<32>>>> {MACMessage, MACAltered};
        test_MACs<MAC::writer<MAC::HMAC<hash::RIPEMD<40>>>> {MACMessage, MACAltered};
        test_MACs<MAC::writer<MAC::HMAC<hash::SHA2<28>>>> {MACMessage, MACAltered};
        test_MACs<MAC::writer<MAC::HMAC<hash::SHA2<32>>>> {MACMessage, MACAltered};
        test_MACs<MAC::writer<MAC::HMAC<hash::SHA2<48>>>> {MACMessage, MACAltered};
        test_MACs<MAC::writer<MAC::HMAC<hash::SHA2<64>>>> {MACMessage, MACAltered};

        HMAC_test_case<hash::SHA1, 20> (bytes (20, 0x0b), "Hi There",
            hash::digest<20> {"b617318655057264e28bc0b6fb378c8ef146be00"});

        HMAC_test_case<hash::SHA1, 4> (bytes (string ("Jefe")), "what do ya want for nothing?",
            hash::digest<20> {"effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"});

        HMAC_test_case<hash::SHA1, 80> (bytes (80, 0xaa), "Test Using Larger Than Block-Size Key - Hash Key First",
            hash::digest<20> {"aa4ae5e15272d00e95705637ce8a3b55ed402112"});

        HMAC_test_case<hash::SHA2<32>, 20> (bytes (20, 0x0b), "Hi There",
            hash::digest<32> {"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"});

        HMAC_test_case<hash::SHA2<32>, 4> (bytes (string ("Jefe")), "what do ya want for nothing?",
            hash::digest<32> {"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"});

        HMAC_test_case<hash::SHA2<32>, 3> (bytes (string ("key")), "",
            hash::digest<32> {"5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0"});

    }

    static_assert (cipher::block::Cipher<cipher::block::AES, 16>);
    static_assert (cipher::block::Cipher<cipher::block::AES, 24>);
    static_assert (cipher::block::Cipher<cipher::block::AES, 32>);

    // taken from
    // https://www.ncbi.nlm.nih.gov/IEB/ToolBox/CPP_DOC/lxr/source/src/connect/mbedtls/cmac.c

    // all test messages are substrings of this.
    static const unsigned char CMAC_test_message[] = {
        /* PT */
        0x6b, 0xc1, 0xbe, 0xe2,     0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11,     0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57,     0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac,     0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46,     0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19,     0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45,     0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b,     0xe6, 0x6c, 0x37, 0x10
    };

    static const unsigned char CMAC_AES_128_key[16] = {
        0x2b, 0x7e, 0x15, 0x16,     0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,     0x09, 0xcf, 0x4f, 0x3c
    };

    static const unsigned char CMAC_AES_192_key[24] = {
        0x8e, 0x73, 0xb0, 0xf7,     0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b,     0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2,     0x52, 0x2c, 0x6b, 0x7b
    };

    static const unsigned char CMAC_AES_256_key[32] = {
        0x60, 0x3d, 0xeb, 0x10,     0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0,     0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07,     0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3,     0x09, 0x14, 0xdf, 0xf4
    };

    static const unsigned char AES_128_expected_result[4][16] =
    {
        {
            /* Example #1 */
            0xbb, 0x1d, 0x69, 0x29,     0xe9, 0x59, 0x37, 0x28,
            0x7f, 0xa3, 0x7d, 0x12,     0x9b, 0x75, 0x67, 0x46
        },
        {
            /* Example #2 */
            0x07, 0x0a, 0x16, 0xb4,     0x6b, 0x4d, 0x41, 0x44,
            0xf7, 0x9b, 0xdd, 0x9d,     0xd0, 0x4a, 0x28, 0x7c
        },
        {
            /* Example #3 */
            0x7d, 0x85, 0x44, 0x9e,     0xa6, 0xea, 0x19, 0xc8,
            0x23, 0xa7, 0xbf, 0x78,     0x83, 0x7d, 0xfa, 0xde
        },
        {
            /* Example #4 */
            0x51, 0xf0, 0xbe, 0xbf,     0x7e, 0x3b, 0x9d, 0x92,
            0xfc, 0x49, 0x74, 0x17,     0x79, 0x36, 0x3c, 0xfe
        }
    };

    static const unsigned char AES_192_expected_result[4][16] =
    {
        {
            /* Example #1 */
            0xd1, 0x7d, 0xdf, 0x46,     0xad, 0xaa, 0xcd, 0xe5,
            0x31, 0xca, 0xc4, 0x83,     0xde, 0x7a, 0x93, 0x67
        },
        {
            /* Example #2 */
            0x9e, 0x99, 0xa7, 0xbf,     0x31, 0xe7, 0x10, 0x90,
            0x06, 0x62, 0xf6, 0x5e,     0x61, 0x7c, 0x51, 0x84
        },
        {
            /* Example #3 */
            0x3d, 0x75, 0xc1, 0x94,     0xed, 0x96, 0x07, 0x04,
            0x44, 0xa9, 0xfa, 0x7e,     0xc7, 0x40, 0xec, 0xf8
        },
        {
            /* Example #4 */
            0xa1, 0xd5, 0xdf, 0x0e,     0xed, 0x79, 0x0f, 0x79,
            0x4d, 0x77, 0x58, 0x96,     0x59, 0xf3, 0x9a, 0x11
        }
    };

    static const unsigned char AES_256_expected_result[4][16] =
    {
        {
            /* Example #1 */
            0x02, 0x89, 0x62, 0xf6,     0x1b, 0x7b, 0xf8, 0x9e,
            0xfc, 0x6b, 0x55, 0x1f,     0x46, 0x67, 0xd9, 0x83
        },
        {
            /* Example #2 */
            0x28, 0xa7, 0x02, 0x3f,     0x45, 0x2e, 0x8f, 0x82,
            0xbd, 0x4b, 0xf2, 0x8d,     0x8c, 0x37, 0xc3, 0x5c
        },
        {
            /* Example #3 */
            0x15, 0x67, 0x27, 0xdc,     0x08, 0x78, 0x94, 0x4a,
            0x02, 0x3c, 0x1f, 0xe0,     0x3b, 0xad, 0x6d, 0x93
        },
        {
            /* Example #4 */
            0xe1, 0x99, 0x21, 0x90,     0x54, 0x9f, 0x6e, 0xd5,
            0x69, 0x6a, 0x2c, 0x05,     0x6c, 0x31, 0x54, 0x10
        }
    };

    template <typename Cipher, size_t key_size>
    requires (cipher::block::Cipher<Cipher, key_size>)
    void CMAC_test_case (
        const unsigned char k[key_size],
        byte_slice msg,
        const unsigned char result[Cipher::BlockSize]) {
        cipher::symmetric_key<key_size> key;
        std::copy (k, k + key_size, key.begin ());
        hash::digest<Cipher::BlockSize> dig;
        std::copy (result, result + Cipher::BlockSize, dig.begin ());
        auto got = CMAC<Cipher, key_size> (key, msg);
        EXPECT_EQ (got, dig) << "CMAC key " << encoding::hex::write (byte_slice {k, key_size}) <<
            " and msg " << encoding::hex::write (msg) << "; expected " << dig << "; got " << got;
    }

    // from rfc4493
    TEST (MAC, CMAC) {
        CMAC_test_case<cipher::block::AES, 128 / 8> (
            CMAC_AES_128_key,
            byte_slice {CMAC_test_message, 0},
            AES_128_expected_result[0]);

        CMAC_test_case<cipher::block::AES, 128 / 8> (
            CMAC_AES_128_key,
            byte_slice {CMAC_test_message, 16},
            AES_128_expected_result[1]);

        CMAC_test_case<cipher::block::AES, 128 / 8> (
            CMAC_AES_128_key,
            byte_slice {CMAC_test_message, 20},
            AES_128_expected_result[2]);

        CMAC_test_case<cipher::block::AES, 128 / 8> (
            CMAC_AES_128_key,
            byte_slice {CMAC_test_message, 64},
            AES_128_expected_result[3]);

        CMAC_test_case<cipher::block::AES, 192 / 8> (
            CMAC_AES_192_key,
            byte_slice {CMAC_test_message, 0},
            AES_192_expected_result[0]);

        CMAC_test_case<cipher::block::AES, 192 / 8> (
            CMAC_AES_192_key,
            byte_slice {CMAC_test_message, 16},
            AES_192_expected_result[1]);

        CMAC_test_case<cipher::block::AES, 192 / 8> (
            CMAC_AES_192_key,
            byte_slice {CMAC_test_message, 20},
            AES_192_expected_result[2]);

        CMAC_test_case<cipher::block::AES, 192 / 8> (
            CMAC_AES_192_key,
            byte_slice {CMAC_test_message, 64},
            AES_192_expected_result[3]);

        CMAC_test_case<cipher::block::AES, 256 / 8> (
            CMAC_AES_256_key,
            byte_slice {CMAC_test_message, 0},
            AES_256_expected_result[0]);

        CMAC_test_case<cipher::block::AES, 256 / 8> (
            CMAC_AES_256_key,
            byte_slice {CMAC_test_message, 16},
            AES_256_expected_result[1]);

        CMAC_test_case<cipher::block::AES, 256 / 8> (
            CMAC_AES_256_key,
            byte_slice {CMAC_test_message, 20},
            AES_256_expected_result[2]);

        CMAC_test_case<cipher::block::AES, 256 / 8> (
            CMAC_AES_256_key,
            byte_slice {CMAC_test_message, 64},
            AES_256_expected_result[3]);

    }
}

namespace crypto::cipher::block {

    // Invalid key and block sizes for a given algorithm should
    // fail to compile, and valid ones should succeed.

    template <typename Cipher, size_t key_size>
    concept TestEncryptable = requires (bytes msg, cipher::symmetric_key<key_size> key) {
        encrypt (block_cipher<Cipher, mode::ECB> {}, key, msg);
        decrypt (block_cipher<Cipher, mode::ECB> {}, key, msg);
    } && requires (bytes msg, cipher::symmetric_key<key_size> key, byte_array<Cipher::BlockSize> iv) {
        encrypt (block_cipher<Cipher, mode::CBC> {iv}, key, msg);
        decrypt (block_cipher<Cipher, mode::CBC> {iv}, key, msg);
        encrypt (block_cipher<Cipher, mode::CFB> {iv}, key, msg);
        decrypt (block_cipher<Cipher, mode::CFB> {iv}, key, msg);
        encrypt (block_cipher<Cipher, mode::OFB> {iv}, key, msg);
        decrypt (block_cipher<Cipher, mode::OFB> {iv}, key, msg);
        encrypt (block_cipher<Cipher, mode::CTR, endian::little> {math::uint_little<Cipher::BlockSize, byte> {iv}}, key, msg);
        decrypt (block_cipher<Cipher, mode::CTR, endian::little> {math::uint_little<Cipher::BlockSize, byte> {iv}}, key, msg);
    };

    static_assert (TestEncryptable<DES, 8>);
    static_assert (!TestEncryptable<DES, 16>);

    static_assert (TestEncryptable<TDEA2, 16>);
    static_assert (TestEncryptable<TDEA3, 24>);

    static_assert (TestEncryptable<AES, 16>);
    static_assert (!TestEncryptable<AES, 8>);
    static_assert (!TestEncryptable<AES, 20>);
    static_assert (TestEncryptable<AES, 24>);
    static_assert (TestEncryptable<AES, 32>);
    static_assert (!TestEncryptable<AES, 56>);

    static_assert (TestEncryptable<Serpent, 16>);
    static_assert (!TestEncryptable<Serpent, 8>);
    static_assert (!TestEncryptable<Serpent, 20>);
    static_assert (TestEncryptable<Serpent, 24>);
    static_assert (TestEncryptable<Serpent, 32>);
    static_assert (!TestEncryptable<Serpent, 56>);

    static_assert (TestEncryptable<Twofish, 16>);
    static_assert (!TestEncryptable<Twofish, 8>);
    static_assert (!TestEncryptable<Twofish, 20>);
    static_assert (TestEncryptable<Twofish, 24>);
    static_assert (TestEncryptable<Twofish, 32>);
    static_assert (!TestEncryptable<Twofish, 56>);

    static_assert (TestEncryptable<RC6, 16>);
    static_assert (!TestEncryptable<RC6, 8>);
    static_assert (!TestEncryptable<RC6, 20>);
    static_assert (TestEncryptable<RC6, 24>);
    static_assert (TestEncryptable<RC6, 32>);
    static_assert (!TestEncryptable<RC6, 56>);

    static_assert (TestEncryptable<MARS, 16>);
    static_assert (!TestEncryptable<MARS, 8>);
    static_assert (!TestEncryptable<MARS, 20>);
    static_assert (TestEncryptable<MARS, 24>);
    static_assert (TestEncryptable<MARS, 32>);
    static_assert (TestEncryptable<MARS, 56>);

    template <typename alg, typename state, typename bc, size_t key_size, typename ...IVs>
    void test_block_cipher (string key, string plaintext, string ciphertext, IVs &&...ivs) {
        byte_array<key_size> k {encoding::hex::fixed<key_size> (key)};

        {
            byte_array<16> pt {encoding::hex::fixed<16> (plaintext)};
            byte_array<16> ct {encoding::hex::fixed<16> (ciphertext)};

            state encryptor {ivs...};
            EXPECT_EQ ((encrypt<alg> (encryptor, k, pt)), ct);
            state decryptor {ivs...};
            auto decrypted = decrypt<alg> (decryptor, k, ct);
            EXPECT_EQ (decrypted, pt) << "Expected " << ct << " to decrypt to " <<
                pt << " using key " << k << " but got " << decrypted;
        }

        // since phase two of the test adds and checks padding, it proves that
        // the block mode correctly inverts itself.
        {
            bytes pt = *encoding::hex::read (plaintext);

            // we test this against the function for encrypting whole messages rather than just blocks.
            auto padded = crypto::encrypt (bc {ivs...}, k, pt);

            // we should expect the encrypted message to have a whole block of padding.
            //EXPECT_EQ (padded.size (), pt.size () + 16);

            bytes ct = *encoding::hex::read (ciphertext);
            EXPECT_EQ (ct, (take (padded, pt.size ())));

            auto decrypted = crypto::decrypt (bc {ivs...}, k, padded);

            EXPECT_EQ (pt, decrypted) << "expected plaintext " << pt << " to equal decrypted " << decrypted;

        }
    }

    template <typename alg, mode m, size_t key_size> struct block_test_case {
        block_test_case (string key, string IV, string plaintext, string ciphertext) {
            test_block_cipher<alg, state<m, alg::BlockSize>, block_cipher<alg, m>, key_size>
            (key, plaintext, ciphertext, byte_array<16> {encoding::hex::fixed<16> (IV)});
        }
    };

    template <typename alg, size_t key_size> struct block_test_case<alg, mode::ECB, key_size> {
        block_test_case (string key, string plaintext, string ciphertext) {
            test_block_cipher<alg, state<mode::ECB>, block_cipher<alg, mode::ECB>, key_size> (key, plaintext, ciphertext);
        }
    };

    template <typename alg, size_t key_size> struct block_test_case<alg, mode::CTR, key_size> {
        block_test_case (string key, string IV, string plaintext, string ciphertext) {
            test_block_cipher<alg, state<mode::CTR, alg::BlockSize, endian::big>, block_cipher<alg, mode::CTR, endian::big>, key_size>
                (key, plaintext, ciphertext, math::uint_big<16, byte> {byte_array<16> {encoding::hex::fixed<16> (IV)}});
        }
    };

    // A series of tests for each block mode with AES to test that the block modes are correct.
    TEST (BlockCipher, ECB) {

        // Since ECB doesn't really do anything, this test
        // proves that the underlying cipher works correctly.
        block_test_case<AES, mode::ECB, 16> {
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "3ad78e726c1ec02b7ebfe92b23d9ec34"};

        block_test_case<AES, mode::ECB, 24> {
            "000000000000000000000000000000000000000000000000",
            "80000000000000000000000000000000",
            "6cd02513e8d4dc986b4afe087a60bd0c"};

        block_test_case<AES, mode::ECB, 32> {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "80000000000000000000000000000000",
            "ddc6bf790c15760d8d9aeb6f9a75fd4e"};

        block_test_case<AES, mode::ECB, 16> {
            "edfdb257cb37cdf182c5455b0c0efebb",
            "1695fe475421cace3557daca01f445ff",
            "7888beae6e7a426332a7eaa2f808e637"};

        block_test_case<AES, mode::ECB, 24> {
            "61396c530cc1749a5bab6fbcf906fe672d0c4ab201af4554",
            "60bcdb9416bac08d7fd0d780353740a5",
            "24f40c4eecd9c49825000fcb4972647a"};

        block_test_case<AES, mode::ECB, 32> {
            "cc22da787f375711c76302bef0979d8eddf842829c2b99ef3dd04e23e54cc24b",
            "ccc62c6b0a09a671d64456818db29a4d",
            "df8634ca02b13a125b786e1dce90658b"};

        block_test_case<Twofish, mode::ECB, 16> {
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "73b9ff14cf2589901ff52a0d6f4b7ede"};

        block_test_case<Serpent, mode::ECB, 16> {
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "a3b35de7c358ddd82644678c64b8bcbb"};

        block_test_case<MARS, mode::ECB, 16> {
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "d962efeba75817bf6ed24bbbb5b7820d"};

        block_test_case<RC6, mode::ECB, 16> {
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "f71f65e7b80c0c6966fee607984b5cdf"};

        block_test_case<Twofish, mode::ECB, 24> {
            "000000000000000000000000000000000000000000000000",
            "80000000000000000000000000000000",
            "62ef193edb7d399aca50ec1cbe5398d8"};

        block_test_case<Serpent, mode::ECB, 24> {
            "000000000000000000000000000000000000000000000000",
            "80000000000000000000000000000000",
            "23f5f432ad687e0d4574c16459618abb"};

        block_test_case<MARS, mode::ECB, 24> {
            "000000000000000000000000000000000000000000000000",
            "80000000000000000000000000000000",
            "4433fccbf2d4aa14783835d0968bb7a6"};

        block_test_case<RC6, mode::ECB, 24> {
            "000000000000000000000000000000000000000000000000",
            "80000000000000000000000000000000",
            "a600b72aac4dfb5271dc45f563fae428"};

        block_test_case<Twofish, mode::ECB, 32> {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "80000000000000000000000000000000",
            "23a385f617f313dac05bcb7eabd61807"};

        block_test_case<Serpent, mode::ECB, 32> {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "80000000000000000000000000000000",
            "8314675e8ad5c3ecd83d852bcf7f566e"};

        block_test_case<MARS, mode::ECB, 32> {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "80000000000000000000000000000000",
            "7dec45d013733a2fc3acb05ac5edcda0"};

        block_test_case<RC6, mode::ECB, 32> {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "80000000000000000000000000000000",
            "30f5c183f6c81a72f39b618b086cc2de"};

        block_test_case<Twofish, mode::ECB, 16> {
            "edfdb257cb37cdf182c5455b0c0efebb",
            "1695fe475421cace3557daca01f445ff",
            "1c0bda78c854cf6b6f7e2b0095659b66"};

        block_test_case<Serpent, mode::ECB, 16> {
            "edfdb257cb37cdf182c5455b0c0efebb",
            "1695fe475421cace3557daca01f445ff",
            "60da3514a0dd32237bdd3546bef56093"};

        block_test_case<MARS, mode::ECB, 16> {
            "edfdb257cb37cdf182c5455b0c0efebb",
            "1695fe475421cace3557daca01f445ff",
            "540848258fc6da64af9410878465d495"};

        block_test_case<RC6, mode::ECB, 16> {
            "edfdb257cb37cdf182c5455b0c0efebb",
            "1695fe475421cace3557daca01f445ff",
            "b8414291d911c6a9d97fc3b49e8c3253"};

        block_test_case<Twofish, mode::ECB, 24> {
            "61396c530cc1749a5bab6fbcf906fe672d0c4ab201af4554",
            "60bcdb9416bac08d7fd0d780353740a5",
            "b9d2d9a16b495e35c7131c502e457543"};

        block_test_case<Serpent, mode::ECB, 24> {
            "61396c530cc1749a5bab6fbcf906fe672d0c4ab201af4554",
            "60bcdb9416bac08d7fd0d780353740a5",
            "915730610cc1f93f2ab72db112655f9e"};

        block_test_case<MARS, mode::ECB, 24> {
            "61396c530cc1749a5bab6fbcf906fe672d0c4ab201af4554",
            "60bcdb9416bac08d7fd0d780353740a5",
            "cb24760bf14501e4134c8eda2f8a0a59"};

        block_test_case<RC6, mode::ECB, 24> {
            "61396c530cc1749a5bab6fbcf906fe672d0c4ab201af4554",
            "60bcdb9416bac08d7fd0d780353740a5",
            "9bd0b1c332e51586ea6888dc6543dcad"};

        block_test_case<Twofish, mode::ECB, 32> {
            "cc22da787f375711c76302bef0979d8eddf842829c2b99ef3dd04e23e54cc24b",
            "ccc62c6b0a09a671d64456818db29a4d",
            "0df2210c88a3aa8fe59a0ac0cf8e80e7"};

        block_test_case<Serpent, mode::ECB, 32> {
            "cc22da787f375711c76302bef0979d8eddf842829c2b99ef3dd04e23e54cc24b",
            "ccc62c6b0a09a671d64456818db29a4d",
            "998b13f6702ace671a59c117524033a1"};

        block_test_case<MARS, mode::ECB, 32> {
            "cc22da787f375711c76302bef0979d8eddf842829c2b99ef3dd04e23e54cc24b",
            "ccc62c6b0a09a671d64456818db29a4d",
            "651a4fb35403c9b72f0ef002e8f58684"};

        block_test_case<RC6, mode::ECB, 32> {
            "cc22da787f375711c76302bef0979d8eddf842829c2b99ef3dd04e23e54cc24b",
            "ccc62c6b0a09a671d64456818db29a4d",
            "c10b5b4c3f20ab5b8a34c13c627eb332"};

    }

    // TODO we need tests for more than just one block.
    TEST (BlockCipher, AESCBC) {
        block_test_case<AES, mode::CBC, 16> {
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "3ad78e726c1ec02b7ebfe92b23d9ec34"};

        block_test_case<AES, mode::CBC, 24> {
            "000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "6cd02513e8d4dc986b4afe087a60bd0c"};

        block_test_case<AES, mode::CBC, 32> {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "ddc6bf790c15760d8d9aeb6f9a75fd4e"};

        block_test_case<AES, mode::CBC, 16> {
            "1f8e4973953f3fb0bd6b16662e9a3c17",
            "2fe2b333ceda8f98f4a99b40d2cd34a8",
            "45cf12964fc824ab76616ae2f4bf0822",
            "0f61c4d44c5147c03c195ad7e2cc12b2"};

        block_test_case<AES, mode::CBC, 24> {
            "ba75f4d1d9d7cf7f551445d56cc1a8ab2a078e15e049dc2c",
            "531ce78176401666aa30db94ec4a30eb",
            "c51fc276774dad94bcdc1d2891ec8668",
            "70dd95a14ee975e239df36ff4aee1d5d"};

        block_test_case<AES, mode::CBC, 32> {
            "6ed76d2d97c69fd1339589523931f2a6cff554b15f738f21ec72dd97a7330907",
            "851e8764776e6796aab722dbb644ace8",
            "6282b8c05c5c1530b97d4816ca434762",
            "6acc04142e100a65f51b97adf5172c41"};

    }

    TEST (BlockCipher, AESCFB) {

        block_test_case<AES, mode::CFB, 16> {
            "085b8af6788fa6bc1a0b47dcf50fbd35",
            "58cb2b12bb52c6f14b56da9210524864",
            "4b5a872260293312eea1a570fd39c788",
            "e92c80e0cfb6d8b1c27fd58bc3708b16"};

        block_test_case<AES, mode::CFB, 24> {
            "1bbb30016d3a908827693352ece9833415433618b1d97595",
            "b2b48e8d60240bf2d9fa05cc2f90c161",
            "b4e499de51e646fad80030da9dc5e7e2",
            "8b7ba98982063a55fca3492269bbe437"};

        block_test_case<AES, mode::CFB, 32> {
            "e1c6e6884eee69552dbfee21f22ca92685d5d08ef0e3f37e5b338c533bb8d72c",
            "cea9f23ae87a637ab0cda6381ecc1202",
            "b72606c98d8e4fabf08839abf7a0ac61",
            "2981761d979bb1765a28b2dd19125b54"};

    }

    TEST (BlockCipher, AESOFB) {

        block_test_case<AES, mode::OFB, 16> {
            "d7d57bd847154af9722a8df096e61a42",
            "fdde201c91e401d9723868c2a612b77a",
            "81883f22165282ba6a442a8dd2a768d4",
            "84cc130b6867623696aa8f523d968ade"};

        block_test_case<AES, mode::OFB, 24> {
            "2943e3edfa815260a8a697b386ca3ae3eee914f22b3857dc",
            "c6995f00318c241217cdc82cf2fa43f9",
            "67e2cf5d63334ae03dbda91100ab781b",
            "225e8bfb133c4332ba6e95ddb841370d"};

        block_test_case<AES, mode::OFB, 32> {
            "6f419b4c683a44d67d234eaa6b57f622f912de657dddb280a14d0cb967ed951f",
            "19b888800ff1d0116124f79dfae54ffe",
            "3d12989faf41ba75bfa70e2bcc2fa222",
            "2d6b005e8d3bc6ea9f62dca36d47aea5"};

    }

    TEST (BlockCipher, AESCTR) {
        block_test_case<AES, mode::CTR, 16> {
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "e6e94bd4ef8a2c3b884cfa59ca342b2e"};

        block_test_case<AES, mode::CTR, 24> {
            "000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "2ae06992acbf52a3e8f4a96ec9300bd7"};

        block_test_case<AES, mode::CTR, 32> {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "5c95c078a2408989ad48a21492842087"};

        block_test_case<AES, mode::CTR, 16> {
            "1f8e4973953f3fb0bd6b16662e9a3c17",
            "2fe2b333ceda8f98f4a99b40d2cd34a8",
            "45cf12964fc824ab76616ae2f4bf0822",
            "a58571b5efb6c81dcc698c18381cb572"};

        block_test_case<AES, mode::CTR, 24> {
            "ba75f4d1d9d7cf7f551445d56cc1a8ab2a078e15e049dc2c",
            "531ce78176401666aa30db94ec4a30eb",
            "c51fc276774dad94bcdc1d2891ec8668",
            "d968c321beda5728e6bd144f04fe0613"};

        block_test_case<AES, mode::CTR, 32> {
            "6ed76d2d97c69fd1339589523931f2a6cff554b15f738f21ec72dd97a7330907",
            "851e8764776e6796aab722dbb644ace8",
            "6282b8c05c5c1530b97d4816ca434762",
            "3eb753155764df1edbfa5793f95d8867"};
    }
}

namespace crypto::cipher {

    // At this point we can say that the AES candidates work and that the block modes mostly work.

    // in order to improve block mode tests, we would add tests for multiple blocks, which
    // are available.

    // we now test that we fail to decrypt messages with the wrong algorithm.

    template <typename...> struct ciphers {};

    byte_array<32> IV1 = byte_array<32> (encoding::hex::fixed<32> {"0123456789abcdef0369cf258be147ad0123456789abcdef0369cf258be147ad"});
    byte_array<32> IV2 = byte_array<32> (encoding::hex::fixed<32> {"1023456789abcdef0369cf258be147ad0123456789abcdef0369cf258be147ad"});

    template <size_t key_size> symmetric_key<key_size> mutate_key (const symmetric_key<key_size> &k) {
        symmetric_key<key_size> new_key = k;
        new_key[0] = ~new_key[0];
        return new_key;
    }

    // Some stuff for testing ciphers with readers and writers.

    constexpr const uint32_little Magic = 0x12345678;

    struct typical_message : string {
        using string::string;
    };

    data::writer<byte> inline &operator << (data::writer<byte> &w, const typical_message &m) {
        return w << Magic << uint32_little {static_cast<uint32> (m.size ())} << bytes (m);
    }

    data::reader<byte> inline &operator >> (data::reader<byte> &r, typical_message &m) {
        uint32_little magic;
        r >> magic;
        if (magic != Magic) throw exception {} << "We ought to find the magic number " << std::hex << Magic << " here, instead we got " << magic;
        uint32_little size;
        r >> size;
        bytes result;
        result.resize (size_t (uint32 (size)));
        r >> result;
        m = typical_message (string (result));
        return r;
    }

}

namespace crypto::cipher::block {

    template <mode m, auto ...rest> struct block_mode {
        constexpr static const mode Mode = m;
    };

    template <typename ...> struct modes {};
    template <padding_scheme ...> struct paddings {};

    template <size_t...sizes>
    using key_sizes = std::index_sequence<sizes...>;

    template <typename cipher, padding_scheme padding, typename mode> struct initialize_algorithm;

    template <typename cipher, padding_scheme padding>
    struct initialize_algorithm<cipher, padding, block_mode<mode::ECB>> {
        block_cipher<cipher, mode::ECB> operator () (const byte_array<32> &IV) {
            return block_cipher<cipher, mode::ECB> {padding};
        };
    };

    template <typename cipher, padding_scheme padding, endian::order r>
    struct initialize_algorithm<cipher, padding, block_mode<mode::CTR, r>> {
        block_cipher<cipher, mode::CTR, r> operator () (const byte_array<32> &IV) {
            math::uint<r, cipher::BlockSize, byte> iv;
            std::copy (IV.begin (), IV.begin () + cipher::BlockSize, iv.begin ());
            return block_cipher<cipher, mode::CTR, r> {iv, padding};
        };
    };

    template <typename cipher, padding_scheme padding, mode m>
    struct initialize_algorithm<cipher, padding, block_mode<m>> {
        block_cipher<cipher, m> operator () (const byte_array<32> &IV) {
            byte_array<cipher::BlockSize> iv;
            std::copy (IV.begin (), IV.begin () + cipher::BlockSize, iv.begin ());
            return block_cipher<cipher, m> {iv, padding};
        };
    };

    template <typename algorithm, size_t key_size>
    void test_block_decrypt_succeed (const algorithm &m, const symmetric_key<key_size> &key, const bytes &ciphertext, const bytes &plaintext) {
        if (!m.valid ()) return;
        bytes decrypted = crypto::decrypt (m, key, ciphertext);
        EXPECT_EQ (plaintext, decrypted) << "tried to decrypt to " << plaintext << " but got " << decrypted;
    }

    template <typename algorithm, size_t key_size>
    void test_block_decrypt_fail (const algorithm &m, const symmetric_key<key_size> &key, const bytes &ciphertext, const bytes &plaintext) {
        if (!m.valid ()) return;
        // we may fail because we throw invalid padding or because
        // the decrypted text does not match, depending on the options.
        try {
            bytes decrypted = crypto::decrypt (m, key, ciphertext);
            EXPECT_NE (plaintext, decrypted);
        } catch (exception &) {}
    }

    template <typename cipher, padding_scheme padding, size_t key_size>
    void test_block_decrypt_wrong_modes (
        const symmetric_key<key_size> &key,
        const bytes &ciphertext,
        const bytes &plaintext,
        modes<>) {}

    template <typename cipher, padding_scheme padding, size_t key_size, mode m, auto ...n, typename ...other_modes>
    void test_block_decrypt_wrong_modes (
        const symmetric_key<key_size> &key,
        const bytes &ciphertext,
        const bytes &plaintext,
        modes<block_mode<m, n...>, other_modes...> om)
    {
        auto algorithm = initialize_algorithm<cipher, padding, block_mode<m, n...>> {} (IV1);
        test_block_decrypt_fail (algorithm, key, ciphertext, plaintext);
        test_block_decrypt_wrong_modes<cipher, padding> (key, ciphertext, plaintext, modes<other_modes...> {});
    }

    template <padding_scheme padding, typename mode, size_t key_size>
    void test_block_decrypt_wrong_ciphers (
        const symmetric_key<key_size> &key,
        const bytes &ciphertext,
        const bytes &plaintext,
        ciphers<>) {}

    template <padding_scheme padding, typename mode, size_t key_size, typename wrong_cipher, typename ...other_ciphers>
    void test_block_decrypt_wrong_ciphers (
        const symmetric_key<key_size> &key,
        const bytes &ciphertext,
        const bytes &plaintext,
        ciphers<wrong_cipher, other_ciphers...> oc)
    {
        if constexpr (Cipher<wrong_cipher, key_size>) {
            auto algorithm = initialize_algorithm<wrong_cipher, padding, mode> {} (IV1);
            test_block_decrypt_fail (algorithm, key, ciphertext, plaintext);
        }

        test_block_decrypt_wrong_ciphers<padding, mode> (key, ciphertext, plaintext, ciphers<other_ciphers...> {});
    }

    template <typename cipher, typename mode, size_t key_size>
    void test_block_decrypt_wrong_padding (
        const symmetric_key<key_size> &key,
        const bytes &ciphertext,
        const bytes &plaintext,
        paddings<>) {}

    template <typename cipher, typename mode, size_t key_size, padding_scheme wrong_padding, padding_scheme ...other_paddings>
    void test_block_decrypt_wrong_padding (
        const symmetric_key<key_size> &key,
        const bytes &ciphertext,
        const bytes &plaintext,
        paddings<wrong_padding, other_paddings...> op)
    {

        if (wrong_padding == padding::NO_PADDING && is_streamable (mode::Mode)) {
            auto algorithm = initialize_algorithm<cipher, wrong_padding, mode> {} (IV1);
            test_block_decrypt_fail (algorithm, key, ciphertext, plaintext);
        }

        test_block_decrypt_wrong_padding<cipher, mode> (key, ciphertext, plaintext, paddings<other_paddings...> {});
    }

    // do nothing if the configuration is not valid.
    template <typename cipher, typename mode, padding_scheme padding, size_t key_size,
        typename ...other_ciphers, typename ...other_modes, padding_scheme ...other_paddings>
    void test_block_cipher (
        const symmetric_key<key_size> &k,
        const bytes &message,
        ciphers<other_ciphers...> oc,
        modes<other_modes...> om,
        paddings<other_paddings...> op) {};

    template <typename cipher, typename mode, padding_scheme padding, size_t key_size,
        typename ...other_ciphers, typename ...other_modes, padding_scheme ...other_paddings>
    requires Cipher<cipher, key_size> && (is_streamable (mode::Mode) || padding != padding::NO_PADDING)
    void test_block_cipher (
        const symmetric_key<key_size> &k,
        const bytes &message,
        ciphers<other_ciphers...> oc,
        modes<other_modes...> om,
        paddings<other_paddings...> op) {

        auto algorithm = initialize_algorithm<cipher, padding, mode> {} (IV1);

        bytes ciphertext = encrypt (algorithm, k, message);

        test_block_decrypt_succeed (algorithm, k, ciphertext, message);

        auto k2 = mutate_key (k);

        test_block_decrypt_fail (algorithm, k2, ciphertext, message);

        if constexpr (mode::Mode != block::mode::ECB) {
            auto wrong_algorithm = initialize_algorithm<cipher, padding, mode> {} (IV2);
            test_block_decrypt_fail (wrong_algorithm, k, ciphertext, message);
        }

        test_block_decrypt_wrong_ciphers<padding, mode> (k, ciphertext, message, oc);
        test_block_decrypt_wrong_modes<cipher, padding> (k, ciphertext, message, om);
        test_block_decrypt_wrong_padding<cipher, mode> (k, ciphertext, message, op);

    };

    template <size_t cipher_index, size_t mode_index, size_t key_index, size_t padding_index,
        typename first_cipher, typename ...rest_ciphers,
        typename first_mode, typename ...rest_modes,
        size_t first_key_size, size_t ...rest_key_sizes,
        padding_scheme first_padding, padding_scheme ...rest_paddings>
    void test_block_ciphers_for (
        const bytes &message,
        ciphers<first_cipher, rest_ciphers...>,
        modes<first_mode, rest_modes...>,
        key_sizes<first_key_size, rest_key_sizes...>,
        paddings<first_padding, rest_paddings...>) {

        if constexpr (cipher_index > sizeof... (rest_ciphers)) return;

        else if constexpr (mode_index > sizeof... (rest_modes))
            return test_block_ciphers_for<cipher_index + 1, 0, 0, 0> (message,
                ciphers<rest_ciphers..., first_cipher> {},
                modes<first_mode, rest_modes...> {},
                key_sizes<first_key_size, rest_key_sizes...> {},
                paddings<first_padding, rest_paddings...> {});

        else if constexpr (key_index > sizeof... (rest_key_sizes))
            return test_block_ciphers_for<cipher_index, mode_index + 1, 0, 0> (message,
                ciphers<first_cipher, rest_ciphers...> {},
                modes<rest_modes..., first_mode> {},
                key_sizes<first_key_size, rest_key_sizes...> {},
                paddings<first_padding, rest_paddings...> {});

        else if constexpr (padding_index > sizeof... (rest_paddings))
            return test_block_ciphers_for<cipher_index, mode_index, key_index + 1, 0> (message,
                ciphers<first_cipher, rest_ciphers...> {},
                modes<first_mode, rest_modes...> {},
                key_sizes<rest_key_sizes..., first_key_size> {},
                paddings<first_padding, rest_paddings...> {});

        else {

            auto key = std::get<cipher::symmetric_key<first_key_size>> (test_keys);

            test_block_cipher<first_cipher, first_mode, first_padding> (key, message,
                ciphers<rest_ciphers...> {}, modes<rest_modes...> {}, paddings<rest_paddings...> {});

            return test_block_ciphers_for<cipher_index, mode_index, key_index, padding_index + 1> (message,
                ciphers<first_cipher, rest_ciphers...> {},
                modes<first_mode, rest_modes...> {},
                key_sizes<first_key_size, rest_key_sizes...> {},
                paddings<rest_paddings..., first_padding> {});
        }
    };

    template <typename ...all_ciphers, typename ...all_modes, size_t ...all_key_sizes, padding_scheme ...all_paddings>
    void test_block_ciphers (
        ciphers<all_ciphers...> c,
        modes<all_modes...> m,
        key_sizes<all_key_sizes...> k,
        paddings<all_paddings...> p,
        const bytes &message) {
        test_block_ciphers_for<0, 0, 0, 0> (message, c, m, k, p);
    }

    // next we test block ciphers.
    ciphers<DES, TDEA2, TDEA3, Rijndael, Serpent, Twofish, MARS, RC6> supported_block_ciphers {};

    modes<
        block_mode<mode::ECB>,
        block_mode<mode::CBC>,
        block_mode<mode::OFB>,
        block_mode<mode::CFB>,
        block_mode<mode::CTR, endian::big>,
        block_mode<mode::CTR, endian::little>> supported_block_modes {};

    paddings<padding::NO_PADDING, padding::ONE_AND_ZEROS_PADDING, padding::PKCS_PADDING> supported_padding {};

    TEST (BlockCipher, EncryptDecrypt) {

        key_sizes<8, 16, 20, 24, 28, 32, 40, 48, 56> key_test_sizes {};

        test_block_ciphers (supported_block_ciphers, supported_block_modes, key_test_sizes, supported_padding,
            bytes {string {"hi, this is a message that is definitely longer than a single block"}});

    }

    // do nothing if the configuration is not valid.
    template <typename cipher, typename mode, padding_scheme padding, size_t key_size,
        typename ...other_ciphers, typename ...other_modes, padding_scheme ...other_paddings>
    void test_block_cipher_writers (
        const symmetric_key<key_size> &k,
        list<typical_message> msgs,
        ciphers<other_ciphers...> oc,
        modes<other_modes...> om,
        paddings<other_paddings...> op) {};

    template <typename cipher, typename mode, padding_scheme padding, size_t key_size,
        typename ...other_ciphers, typename ...other_modes, padding_scheme ...other_paddings>
    requires Cipher<cipher, key_size> && (is_streamable (mode::Mode) || padding != padding::NO_PADDING)
    void test_block_cipher_writers (
        const symmetric_key<key_size> &k,
        list<typical_message> msgs,
        ciphers<other_ciphers...> oc,
        modes<other_modes...> om,
        paddings<other_paddings...> op) {

        data::random::std_random<std::default_random_engine> iv_generator {237};

        using algorithm = block_cipher<cipher, mode::Mode>;
        using encryptor = crypto::cipher::writer<encryption, algorithm, key_size>;
        using decryptor = crypto::cipher::reader<decryption, algorithm, key_size>;

        bytes encrypted = build_with<bytes, lazy_bytes_writer> ([&] (auto &&w) {
            for (const typical_message &m : msgs) {
                initialization_vector<cipher::BlockSize> iv {};
                iv_generator >> iv;
                w << iv;
                encryptor e {algorithm {iv}, k, w};
                e << m;
            }
        });

        iterator_reader r {encrypted.begin (), encrypted.end ()};

        for (const typical_message &m : msgs) {
            initialization_vector<cipher::BlockSize> iv {};
            r >> iv;
            decryptor d {algorithm {iv}, k, r};
            typical_message tm;
            d >> tm;
            EXPECT_EQ (tm, m);
        }

    };

    template <size_t cipher_index, size_t mode_index, size_t key_index, size_t padding_index,
        typename first_cipher, typename ...rest_ciphers,
        typename first_mode, typename ...rest_modes,
        size_t first_key_size, size_t ...rest_key_sizes,
        padding_scheme first_padding, padding_scheme ...rest_paddings>
    void test_block_cipher_writers_for (
        list<typical_message> msgs,
        ciphers<first_cipher, rest_ciphers...>,
        modes<first_mode, rest_modes...>,
        key_sizes<first_key_size, rest_key_sizes...>,
        paddings<first_padding, rest_paddings...>) {

        if constexpr (cipher_index > sizeof... (rest_ciphers)) return;

        else if constexpr (mode_index > sizeof... (rest_modes))
            return test_block_cipher_writers_for<cipher_index + 1, 0, 0, 0> (msgs,
                ciphers<rest_ciphers..., first_cipher> {},
                modes<first_mode, rest_modes...> {},
                key_sizes<first_key_size, rest_key_sizes...> {},
                paddings<first_padding, rest_paddings...> {});

        else if constexpr (key_index > sizeof... (rest_key_sizes))
            return test_block_cipher_writers_for<cipher_index, mode_index + 1, 0, 0> (msgs,
                ciphers<first_cipher, rest_ciphers...> {},
                modes<rest_modes..., first_mode> {},
                key_sizes<first_key_size, rest_key_sizes...> {},
                paddings<first_padding, rest_paddings...> {});

        else if constexpr (padding_index > sizeof... (rest_paddings))
            return test_block_cipher_writers_for<cipher_index, mode_index, key_index + 1, 0> (msgs,
                ciphers<first_cipher, rest_ciphers...> {},
                modes<first_mode, rest_modes...> {},
                key_sizes<rest_key_sizes..., first_key_size> {},
                paddings<first_padding, rest_paddings...> {});

        else {
            auto key = std::get<cipher::symmetric_key<first_key_size>> (test_keys);

            test_block_cipher_writers<first_cipher, first_mode, first_padding> (key, msgs,
                ciphers<rest_ciphers...> {}, modes<rest_modes...> {}, paddings<rest_paddings...> {});

            return test_block_cipher_writers_for<cipher_index, mode_index, key_index, padding_index + 1> (msgs,
                ciphers<first_cipher, rest_ciphers...> {},
                modes<first_mode, rest_modes...> {},
                key_sizes<first_key_size, rest_key_sizes...> {},
                paddings<rest_paddings..., first_padding> {});
        }
    };

    template <typename ...all_ciphers, typename ...all_modes, size_t ...all_key_sizes, padding_scheme ...all_paddings>
    void test_block_cipher_writers (
        ciphers<all_ciphers...> c,
        modes<all_modes...> m,
        key_sizes<all_key_sizes...> k,
        paddings<all_paddings...> p,
        list<typical_message> msgs) {
        test_block_cipher_writers_for<0, 0, 0, 0> (msgs, c, m, k, p);
    }

    // we only test modes that have a standard IV type.
    // this ought to be good enough since all modes a
    // are tested properly above.
    modes<
        block_mode<mode::CBC>,
        block_mode<mode::OFB>,
        block_mode<mode::CFB>> read_write_test_modes {};

    TEST (BlockCipher, WriteRead) {

        key_sizes<8, 16, 20, 24, 28, 32, 40, 48, 56> key_test_sizes {};

        test_block_cipher_writers (supported_block_ciphers, read_write_test_modes, key_test_sizes, supported_padding,
            list<typical_message> {
                typical_message {""},
                typical_message {"abcde"},
                typical_message {string {"hi, this is a message that is definitely longer than a single block"}}});

    }
}

namespace crypto::cipher {

    ciphers<stream::XChaCha20, stream::XSalsa20, stream::Salsa20,
        stream::HC128, stream::HC256, stream::Panama,
        block_cipher<block::AES, cipher::block::mode::OFB>,
        block_cipher<block::AES, cipher::block::mode::CTR, endian::big>,
        block_cipher<block::AES, cipher::block::mode::CTR, endian::little>> supported_stream_ciphers {};

    using IV_sizes = std::index_sequence<24, 24, 8, 16, 32, 32, 16, 16, 16>;

    template <typename alg, size_t key_size, typename IV>
    void stream_encrypt_and_decrypt (const cipher::symmetric_key<key_size> &key, const IV &iv, const bytes &message) {
        bytes decrypted = decrypt<alg> (key, iv, encrypt<alg> (key, iv, message));
        EXPECT_EQ (message, decrypted) << "tried to decrypt to " << message << " but got " << decrypted;
    }

    template <typename alg, size_t key_size, typename IV>
    void test_stream_cipher (
        const symmetric_key<key_size> &k1,
        const symmetric_key<key_size> &k2,
        const IV &iv,
        const bytes &message) {}

    template <typename alg, size_t key_size, typename IV>
    requires requires (const symmetric_key<key_size> &k, const IV &iv) {
        alg {k, iv};
    } void test_stream_cipher (
        const symmetric_key<key_size> &k1,
        const symmetric_key<key_size> &k2,
        const IV &iv,
        const bytes &message) {

        stream_encrypt_and_decrypt<alg> (k1, iv, message);
        stream_encrypt_and_decrypt<alg> (k2, iv, message);

    }

    template <size_t cipher_index, size_t key_index,
        typename... cph, size_t ...key_sizes, size_t ...iv_sizes>
    void test_stream_ciphers_for (ciphers<cph...> c, keys<key_sizes...> k, const bytes &msg, std::index_sequence<iv_sizes...> ivs) {
        if constexpr (cipher_index >= sizeof... (cph)) return;
        else if constexpr (key_index >= sizeof... (key_sizes))
            test_stream_ciphers_for<cipher_index + 1, 0> (c, k, msg, ivs);
        else {

            auto key = std::get<key_index> (k);
            using cipher = typename meta::get_type<cipher_index, cph...>::type;
            constexpr static const size_t iv_size = meta::get_value<cipher_index, iv_sizes...>::value;

            byte_array<iv_size> iv;
            std::copy (IV1.begin (), IV1.begin () + iv_size, iv.begin ());
            test_stream_cipher<cipher> (key, mutate_key (key), iv, msg);

            test_stream_ciphers_for<cipher_index, key_index + 1> (c, k, msg, ivs);
        }
    }

    template <typename... cph, typename keys, typename IV_sizes>
    void test_stream_ciphers (ciphers<cph...> c, keys k, const bytes &msg, const IV_sizes &ivs) {
        test_stream_ciphers_for<0, 0> (c, k, msg, ivs);
    }

    TEST (CryptoppStreamCipher, Crypt) {

        test_stream_ciphers (supported_stream_ciphers, test_keys, bytes {string {""}}, IV_sizes {});
        test_stream_ciphers (supported_stream_ciphers, test_keys, bytes {string {"a"}}, IV_sizes {});
        test_stream_ciphers (supported_stream_ciphers, test_keys,
            bytes {string {"hi, this is a message that is definitely longer than a single block"}}, IV_sizes {});

    }

}

// TODO Keccak
