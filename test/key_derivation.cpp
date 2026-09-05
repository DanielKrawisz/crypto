// Copyright (c) 2025 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <data/bytes.hpp>
#include <data/array.hpp>
#include <data/numbers.hpp>

#include <crypto/hash.hpp>
#include <crypto/PKCS5_PBKDF2_HMAC.hpp>
#include <crypto/HKDF.hpp>

namespace crypto::cipher {

    // from RFC 6070 and https://github.com/brycx/Test-Vector-Generation/blob/master/PBKDF2/pbkdf2-hmac-sha2-test-vectors.md
    TEST (KeyDerivation, PKCS5_PBKDF2_HMAC) {

        {
            bytes password {string {"password"}};
            string salt {"salt"};

            {
                auto expected = cipher::symmetric_key<20> (encoding::hex::fixed<20> {"0c60c80f961f0e71f3a9b524af6012062fe037a6"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA1> (password, 1, bytes (salt));

                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = cipher::symmetric_key<20> (encoding::hex::fixed<20> {"3c198cbdb9464b7857966bd05b7bc92bc1cc4e6e"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA2_224> (password, 1, bytes (salt));

                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = cipher::symmetric_key<20> (encoding::hex::fixed<20> {"120fb6cffcf8b32c43e7225256c4f837a86548c9"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA2_256> (password, 1, bytes (salt));

                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = cipher::symmetric_key<20> (encoding::hex::fixed<20> {"c0e14f06e49e32d73f9f52ddf1d0c5c719160923"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA2_384> (password, 1, bytes (salt));

                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = cipher::symmetric_key<20> (encoding::hex::fixed<20> {"867f70cf1ade02cff3752599a3a53dc4af34c7a6"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA2_512> (password, 1, bytes (salt));

                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }
        }

        {
            bytes password {string {"password"}};
            string salt {"salt"};

            {
                auto expected = symmetric_key<20> (encoding::hex::fixed<20> {
                    "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA1> (password, 2, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<20> (encoding::hex::fixed<20> {
                    "93200ffa96c5776d38fa10abdf8f5bfc0054b971"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA2_224> (password, 2, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<20> (encoding::hex::fixed<20> {
                    "ae4d0c95af6b46d32d0adff928f06dd02a303f8e"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA2_256> (password, 2, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<20> (encoding::hex::fixed<20> {
                    "54f775c6d790f21930459162fc535dbf04a93918"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA2_384> (password, 2, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<20> (encoding::hex::fixed<20> {
                    "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA2_512> (password, 2, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }
        }

        {
            bytes password {string {"password"}};
            string salt {"salt"};

            {
                auto expected = symmetric_key<20> (encoding::hex::fixed<20> {
                    "4b007901b765489abead49d926f721d065a429c1"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA1> (password, 4096, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<20> (encoding::hex::fixed<20> {
                    "218c453bf90635bd0a21a75d172703ff6108ef60"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA2_224> (password, 4096, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<20> (encoding::hex::fixed<20> {
                    "c5e478d59288c841aa530db6845c4c8d962893a0"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA2_256> (password, 4096, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<20> (encoding::hex::fixed<20> {
                    "559726be38db125bc85ed7895f6e3cf574c7a01c"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA2_384> (password, 4096, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<20> (encoding::hex::fixed<20> {
                    "d197b1b33db0143e018b12f3d1d1479e6cdebdcc"});
                auto result = PKCS5_PBKDF2_HMAC<20, hash::SHA2_512> (password, 4096, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }
        }

        {
            bytes password {string {"passwordPASSWORDpassword"}};
            string salt {"saltSALTsaltSALTsaltSALTsaltSALTsalt"};

            {
                auto expected = symmetric_key<25> (encoding::hex::fixed<25> {
                    "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"});
                auto result = PKCS5_PBKDF2_HMAC<25, hash::SHA1> (password, 4096, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<25> (encoding::hex::fixed<25> {
                    "056c4ba438ded91fc14e0594e6f52b87e1f3690c0dc0fbc057"});
                auto result = PKCS5_PBKDF2_HMAC<25, hash::SHA2_224> (password, 4096, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<25> (encoding::hex::fixed<25> {
                    "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c"});
                auto result = PKCS5_PBKDF2_HMAC<25, hash::SHA2_256> (password, 4096, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<25> (encoding::hex::fixed<25> {
                    "819143ad66df9a552559b9e131c52ae6c5c1b0eed18f4d283b"});
                auto result = PKCS5_PBKDF2_HMAC<25, hash::SHA2_384> (password, 4096, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<25> (encoding::hex::fixed<25> {
                    "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868"});
                auto result = PKCS5_PBKDF2_HMAC<25, hash::SHA2_512> (password, 4096, bytes (salt));
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }
        }

        {
            bytes password {'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd'};
            bytes salt {'s', 'a', 0, 'l', 't'};

            {
                auto expected = symmetric_key<16> (encoding::hex::fixed<16> {
                    "56fa6aa75548099dcc37d7f03425e0c3"});
                auto result = PKCS5_PBKDF2_HMAC<16, hash::SHA1> (password, 4096, salt);
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<16> (encoding::hex::fixed<16> {
                    "9b4011b641f40a2a500a31d4a392d15c"});
                auto result = PKCS5_PBKDF2_HMAC<16, hash::SHA2_224> (password, 4096, salt);
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<16> (encoding::hex::fixed<16> {
                    "89b69d0516f829893c696226650a8687"});
                auto result = PKCS5_PBKDF2_HMAC<16, hash::SHA2_256> (password, 4096, salt);
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<16> (encoding::hex::fixed<16> {
                    "a3f00ac8657e095f8e0823d232fc60b3"});
                auto result = PKCS5_PBKDF2_HMAC<16, hash::SHA2_384> (password, 4096, salt);
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

            {
                auto expected = symmetric_key<16> (encoding::hex::fixed<16> {
                    "9d9e9c4cd21fe4be24d5b8244c759665"});
                auto result = PKCS5_PBKDF2_HMAC<16, hash::SHA2_512> (password, 4096, salt);
                EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
            }

        }

        {
            bytes password {string {"passwd"}};
            string salt {"salt"};
            auto expected = symmetric_key<64> (encoding::hex::fixed<64> {
                "55ac046e56e3089fec1691c22544b605"
                "f94185216dde0465e68b9d57c20dacbc"
                "49ca9cccf179b645991664b39d77ef31"
                "7c71b845b1e30bd509112041d3a19783"});
            auto result = PKCS5_PBKDF2_HMAC<64, hash::SHA2_256> (password, 1, bytes (salt));
            EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
        }

        {
            bytes password {string {"Password"}};
            string salt {"NaCl"};
            auto expected = symmetric_key<64> (encoding::hex::fixed<64> {
                "4ddcd8f60b98be21830cee5ef22701f9"
                "641a4418d04c0414aeff08876b34ab56"
                "a1d425a1225833549adb841b51c9b317"
                "6a272bdebba1d078478f62b397f33c8d"});
            auto result = PKCS5_PBKDF2_HMAC<64, hash::SHA2_256> (password, 80000, bytes (salt));
            EXPECT_EQ (expected, result) << "expected " << expected << " but got " << result;
        }

    }

    // From RFC 5869
    TEST (KeyDerivation, HKDF) {
        {
            using hkdf = HKDF<hash::SHA2_256>;

            auto IKM = bytes (encoding::hex::string {
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"});
            auto salt = byte_array<13> (encoding::hex::fixed<13> {
                "000102030405060708090a0b0c"});
            auto info = bytes (encoding::hex::string {
                "f0f1f2f3f4f5f6f7f8f9"});
            size_t len = 42;
            auto PRK = byte_array<32> (encoding::hex::fixed<32> {
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"});
            auto OKM = bytes (encoding::hex::string {
                "3cb25f25faacd57a90434f64d0362f2a"
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865"});

            EXPECT_EQ (PRK, hkdf::extract (IKM, salt));
            auto result = hkdf (PRK, info, len).Result;
            EXPECT_EQ (OKM, result) << "expected " << OKM << " but got " << result;
        }

        {
            using hkdf = HKDF<hash::SHA2_256>;

            auto IKM = bytes (encoding::hex::string {
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f"
                "303132333435363738393a3b3c3d3e3f"
                "404142434445464748494a4b4c4d4e4f"});
            auto salt = byte_array<80> (encoding::hex::fixed<80> {
                "606162636465666768696a6b6c6d6e6f"
                "707172737475767778797a7b7c7d7e7f"
                "808182838485868788898a8b8c8d8e8f"
                "909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"});
            auto info = bytes (encoding::hex::string {
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"});
            size_t len = 82;
            auto PRK = byte_array<32> (encoding::hex::fixed<32> {
                "06a6b88c5853361a06104c9ceb35b45c"
                "ef760014904671014a193f40c15fc244"});
            auto OKM = bytes (encoding::hex::string {
                "b11e398dc80327a1c8e7f78c596a4934"
                "4f012eda2d4efad8a050cc4c19afa97c"
                "59045a99cac7827271cb41c65e590e09"
                "da3275600c2f09b8367793a9aca3db71"
                "cc30c58179ec3e87c14c01d5c1f3434f"
                "1d87"});

            EXPECT_EQ (PRK, hkdf::extract (IKM, salt));
            EXPECT_EQ (OKM, hkdf (PRK, info, len).Result);
        }

        {
            using hkdf = HKDF<hash::SHA2_256>;

            auto IKM = bytes (encoding::hex::string {
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"});
            auto salt = byte_array<0> (encoding::hex::fixed<0> {""});
            auto info = bytes (encoding::hex::string {""});
            size_t len = 42;
            auto PRK = byte_array<32> (encoding::hex::fixed<32> {
                "19ef24a32c717b167f33a91d6f648bdf"
                "96596776afdb6377ac434c1c293ccb04"});
            auto OKM = bytes (encoding::hex::string {
                "8da4e775a563c18f715f802a063c5a31"
                "b8a11f5c5ee1879ec3454e5f3c738d2d"
                "9d201395faa4b61a96c8"});

            EXPECT_EQ (PRK, hkdf::extract (IKM, salt));
            EXPECT_EQ (OKM, hkdf (PRK, info, len).Result);
        }

        {
            using hkdf = HKDF<hash::SHA1>;

            auto IKM = bytes (encoding::hex::string {
                "0b0b0b0b0b0b0b0b0b0b0b"});
            auto salt = byte_array<13> (encoding::hex::fixed<13> {
                "000102030405060708090a0b0c"});
            auto info = bytes (encoding::hex::string {
                "f0f1f2f3f4f5f6f7f8f9"});
            size_t len = 42;
            auto PRK = byte_array<20> (encoding::hex::fixed<20> {
                "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243"});
            auto OKM = bytes (encoding::hex::string {
                "085a01ea1b10f36933068b56efa5ad81"
                "a4f14b822f5b091568a9cdd4f155fda2"
                "c22e422478d305f3f896"});

            EXPECT_EQ (PRK, hkdf::extract (IKM, salt));
            EXPECT_EQ (OKM, hkdf (PRK, info, len).Result);
        }

        {
            using hkdf = HKDF<hash::SHA1>;

            auto IKM = bytes (encoding::hex::string {
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f"
                "303132333435363738393a3b3c3d3e3f"
                "404142434445464748494a4b4c4d4e4f"});
            auto salt = byte_array<80> (encoding::hex::fixed<80> {
                "606162636465666768696a6b6c6d6e6f"
                "707172737475767778797a7b7c7d7e7f"
                "808182838485868788898a8b8c8d8e8f"
                "909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"});
            auto info = bytes (encoding::hex::string {
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"});
            size_t len = 82;
            auto PRK = byte_array<20> (encoding::hex::fixed<20> {
                "8adae09a2a307059478d309b26c4115a224cfaf6"});
            auto OKM = bytes (encoding::hex::string {
                "0bd770a74d1160f7c9f12cd5912a06eb"
                "ff6adcae899d92191fe4305673ba2ffe"
                "8fa3f1a4e5ad79f3f334b3b202b2173c"
                "486ea37ce3d397ed034c7f9dfeb15c5e"
                "927336d0441f4c4300e2cff0d0900b52"
                "d3b4"});

            EXPECT_EQ (PRK, hkdf::extract (IKM, salt));
            EXPECT_EQ (OKM, hkdf (PRK, info, len).Result);
        }

        {
            using hkdf = HKDF<hash::SHA1>;

            auto IKM = bytes (encoding::hex::string {
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"});
            auto salt = byte_array<0> (encoding::hex::fixed<0> {""});
            auto info = bytes (encoding::hex::string {""});
            size_t len = 42;
            auto PRK = byte_array<20> (encoding::hex::fixed<20> {
                "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01"});
            auto OKM = bytes (encoding::hex::string {
                "0ac1af7002b3d761d1e55298da9d0506"
                "b9ae52057220a306e07b6b87e8df21d0"
                "ea00033de03984d34918"});

            EXPECT_EQ (PRK, hkdf::extract (IKM, salt));
            EXPECT_EQ (OKM, hkdf (PRK, info, len).Result);
        }
        {
            using hkdf = HKDF<hash::SHA1>;

            auto IKM = bytes (encoding::hex::string {
                "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"});
            auto info = bytes (encoding::hex::string {""});
            size_t len = 42;
            auto PRK = byte_array<20> (encoding::hex::fixed<20> {
                "2adccada18779e7c2077ad2eb19d3f3e731385dd"});
            auto OKM = bytes (encoding::hex::string {
                "2c91117204d745f3500d636a62f64f0a"
                "b3bae548aa53d423b0d1f27ebba6f5e5"
                "673a081d70cce7acfc48"});

            EXPECT_EQ (PRK, hkdf::extract (IKM));
            EXPECT_EQ (OKM, hkdf (PRK, info, len).Result);
        }
    }
}
