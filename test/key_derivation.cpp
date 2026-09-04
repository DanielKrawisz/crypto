// Copyright (c) 2025 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <data/bytes.hpp>
#include <data/array.hpp>
#include <data/numbers.hpp>

#include <crypto/hash.hpp>
#include <crypto/PKCS5_PBKDF2_HMAC.hpp>

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

}
