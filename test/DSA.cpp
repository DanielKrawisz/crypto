// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include <crypto/DSA.hpp>
#include <data/math/algebra/finite_field.hpp>
#include <data/math/number/NTL/random.hpp>

namespace crypto {

    template <typename G> struct test_DSA {
        test_DSA (random::source &oo, const G::digest &h1, const G::digest &h2) {

            EXPECT_NE (h1, h2);

            // generate keys
            typename G::secret secret1 = G::generate_key (oo);
            typename G::secret secret2;
            do {
                oo >> secret2;
            } while (secret1 == secret2);

            EXPECT_TRUE (secret1.valid ());
            EXPECT_TRUE (secret2.valid ());

            EXPECT_NE (secret1, secret2);

            // generate public key
            auto pubkey1 = secret1.to_public ();
            auto pubkey2 = secret2.to_public ();

            EXPECT_NE (pubkey1, pubkey2);

            auto signed11 = secret1.sign (h1, oo);
            auto signed12 = secret1.sign (h2, oo);
            auto signed21 = secret2.sign (h1, oo);
            auto signed22 = secret2.sign (h2, oo);

            EXPECT_NE (signed11, signed12);
            EXPECT_NE (signed11, signed21);
            EXPECT_NE (signed11, signed22);

            EXPECT_TRUE (pubkey1.verify (signed11, h1));
            EXPECT_TRUE (pubkey1.verify (signed12, h2));
            EXPECT_TRUE (pubkey2.verify (signed21, h1));
            EXPECT_TRUE (pubkey2.verify (signed22, h2));

            EXPECT_FALSE (pubkey1.verify (signed11, h2));
            EXPECT_FALSE (pubkey1.verify (signed12, h1));
            EXPECT_FALSE (pubkey2.verify (signed21, h2));
            EXPECT_FALSE (pubkey2.verify (signed22, h1));

            EXPECT_FALSE (pubkey2.verify (signed11, h1));
            EXPECT_FALSE (pubkey2.verify (signed12, h2));
            EXPECT_FALSE (pubkey1.verify (signed21, h1));
            EXPECT_FALSE (pubkey1.verify (signed22, h2));
        }

    };

    using safe_17_bit_primes = ::testing::Types<
        DSA<math::prime_field<uint64 {65543}>  {uint64 {25}}, uint64 {32771}>,
        DSA<math::prime_field<uint64 {65579}>  {uint64 {4}},  uint64 {32789}>,
        DSA<math::prime_field<uint64 {65687}>  {uint64 {25}}, uint64 {32843}>,
        DSA<math::prime_field<uint64 {65867}>  {uint64 {4}},  uint64 {32933}>,
        DSA<math::prime_field<uint64 {66047}>  {uint64 {25}}, uint64 {33023}>,
        DSA<math::prime_field<uint64 {66107}>  {uint64 {4}},  uint64 {33053}>,
        DSA<math::prime_field<uint64 {66239}>  {uint64 {289}}, uint64 {33119}>,
        DSA<math::prime_field<uint64 {66359}>  {uint64 {169}}, uint64 {33179}>,
        DSA<math::prime_field<uint64 {66383}>  {uint64 {25}}, uint64 {33191}>,
        DSA<math::prime_field<uint64 {66923}>  {uint64 {4}},  uint64 {33461}>,
        DSA<math::prime_field<uint64 {66959}>  {uint64 {49}}, uint64 {33479}>,
        DSA<math::prime_field<uint64 {67043}>  {uint64 {4}},  uint64 {33521}>,
        DSA<math::prime_field<uint64 {67139}>  {uint64 {4}},  uint64 {33569}>,
        DSA<math::prime_field<uint64 {67247}>  {uint64 {25}}, uint64 {33623}>,
        DSA<math::prime_field<uint64 {67427}>  {uint64 {4}},  uint64 {33713}>,
        DSA<math::prime_field<uint64 {67499}>  {uint64 {4}},  uint64 {33749}>,
        DSA<math::prime_field<uint64 {67547}>  {uint64 {4}},  uint64 {33773}>,
        DSA<math::prime_field<uint64 {67619}>  {uint64 {4}},  uint64 {33809}>,
        DSA<math::prime_field<uint64 {67883}>  {uint64 {4}},  uint64 {33941}>,
        DSA<math::prime_field<uint64 {68507}>  {uint64 {4}},  uint64 {34253}>,
        DSA<math::prime_field<uint64 {68567}>  {uint64 {25}}, uint64 {34283}>,
        DSA<math::prime_field<uint64 {68639}>  {uint64 {49}}, uint64 {34319}>,
        DSA<math::prime_field<uint64 {68879}>  {uint64 {169}}, uint64 {34439}>,
        DSA<math::prime_field<uint64 {69263}>  {uint64 {25}},  uint64 {34631}>,
        DSA<math::prime_field<uint64 {69767}>  {uint64 {25}},  uint64 {34883}>,
        DSA<math::prime_field<uint64 {69827}>  {uint64 {4}},   uint64 {34913}>,
        DSA<math::prime_field<uint64 {69899}>  {uint64 {4}},   uint64 {34949}>,
        DSA<math::prime_field<uint64 {70139}>  {uint64 {4}},   uint64 {35069}>,
        DSA<math::prime_field<uint64 {70163}>  {uint64 {4}},   uint64 {35081}>,
        DSA<math::prime_field<uint64 {70199}>  {uint64 {289}}, uint64 {35099}>,
        DSA<math::prime_field<uint64 {70223}>  {uint64 {25}},  uint64 {35111}>,
        DSA<math::prime_field<uint64 {70583}>  {uint64 {25}},  uint64 {35291}>,
        DSA<math::prime_field<uint64 {71147}>  {uint64 {4}},   uint64 {35573}>,
        DSA<math::prime_field<uint64 {71663}>  {uint64 {25}},  uint64 {35831}>,
        DSA<math::prime_field<uint64 {71867}>  {uint64 {4}},   uint64 {35933}>,
        DSA<math::prime_field<uint64 {71987}>  {uint64 {4}},   uint64 {35993}>,
        DSA<math::prime_field<uint64 {71999}>  {uint64 {49}},  uint64 {35999}>,
        DSA<math::prime_field<uint64 {72167}>  {uint64 {25}},  uint64 {36083}>,
        DSA<math::prime_field<uint64 {72383}>  {uint64 {25}},  uint64 {36191}>,
        DSA<math::prime_field<uint64 {72503}>  {uint64 {25}},  uint64 {36251}>,
        DSA<math::prime_field<uint64 {72707}>  {uint64 {4}},   uint64 {36353}>,
        DSA<math::prime_field<uint64 {72767}>  {uint64 {25}},  uint64 {36383}>,
        DSA<math::prime_field<uint64 {72959}>  {uint64 {289}}, uint64 {36479}>,
        DSA<math::prime_field<uint64 {73127}>  {uint64 {25}},  uint64 {36563}>,
        DSA<math::prime_field<uint64 {73259}>  {uint64 {4}},   uint64 {36629}>,
        DSA<math::prime_field<uint64 {73523}>  {uint64 {4}},   uint64 {36761}>,
        DSA<math::prime_field<uint64 {73583}>  {uint64 {25}},  uint64 {36791}>,
        DSA<math::prime_field<uint64 {73643}>  {uint64 {4}},   uint64 {36821}>,
        DSA<math::prime_field<uint64 {73847}>  {uint64 {25}},  uint64 {36923}>,
        DSA<math::prime_field<uint64 {73859}>  {uint64 {4}},   uint64 {36929}>,
        DSA<math::prime_field<uint64 {74027}>  {uint64 {4}},   uint64 {37013}>,
        DSA<math::prime_field<uint64 {74099}>  {uint64 {4}},   uint64 {37049}>,
        DSA<math::prime_field<uint64 {74279}>  {uint64 {49}},  uint64 {37139}>,
        DSA<math::prime_field<uint64 {74363}>  {uint64 {4}},   uint64 {37181}>,
        DSA<math::prime_field<uint64 {74507}>  {uint64 {4}},   uint64 {37253}>,
        DSA<math::prime_field<uint64 {74759}>  {uint64 {121}}, uint64 {37379}>,
        DSA<math::prime_field<uint64 {75239}>  {uint64 {169}}, uint64 {37619}>,
        DSA<math::prime_field<uint64 {75707}>  {uint64 {4}},   uint64 {37853}>,
        DSA<math::prime_field<uint64 {75743}>  {uint64 {25}},  uint64 {37871}>,
        DSA<math::prime_field<uint64 {75983}>  {uint64 {25}},  uint64 {37991}>,
        DSA<math::prime_field<uint64 {76079}>  {uint64 {121}}, uint64 {38039}>,
        DSA<math::prime_field<uint64 {76367}>  {uint64 {25}},  uint64 {38183}>,
        DSA<math::prime_field<uint64 {76379}>  {uint64 {4}},   uint64 {38189}>,
        DSA<math::prime_field<uint64 {76403}>  {uint64 {4}},   uint64 {38201}>,
        DSA<math::prime_field<uint64 {76463}>  {uint64 {25}},  uint64 {38231}>,
        DSA<math::prime_field<uint64 {76607}>  {uint64 {25}},  uint64 {38303}>,
        DSA<math::prime_field<uint64 {76667}>  {uint64 {4}},   uint64 {38333}>,
        DSA<math::prime_field<uint64 {76907}>  {uint64 {4}},   uint64 {38453}>,
        DSA<math::prime_field<uint64 {76919}>  {uint64 {169}}, uint64 {38459}>,
        DSA<math::prime_field<uint64 {77003}>  {uint64 {4}},   uint64 {38501}>,
        DSA<math::prime_field<uint64 {77279}>  {uint64 {121}}, uint64 {38639}>,
        DSA<math::prime_field<uint64 {77339}>  {uint64 {4}},   uint64 {38669}>,
        DSA<math::prime_field<uint64 {77447}>  {uint64 {25}},  uint64 {38723}>,
        DSA<math::prime_field<uint64 {77723}>  {uint64 {4}},   uint64 {38861}>,
        DSA<math::prime_field<uint64 {77747}>  {uint64 {4}},   uint64 {38873}>,
        DSA<math::prime_field<uint64 {77783}>  {uint64 {25}},  uint64 {38891}>,
        DSA<math::prime_field<uint64 {77867}>  {uint64 {4}},   uint64 {38933}>,
        DSA<math::prime_field<uint64 {78179}>  {uint64 {4}},   uint64 {39089}>,
        DSA<math::prime_field<uint64 {78467}>  {uint64 {4}},   uint64 {39233}>,
        DSA<math::prime_field<uint64 {78479}>  {uint64 {49}},  uint64 {39239}>,
        DSA<math::prime_field<uint64 {78839}>  {uint64 {169}}, uint64 {39419}>,
        DSA<math::prime_field<uint64 {78887}>  {uint64 {25}},  uint64 {39443}>,
        DSA<math::prime_field<uint64 {79043}>  {uint64 {4}},   uint64 {39521}>,
        DSA<math::prime_field<uint64 {79103}>  {uint64 {25}},  uint64 {39551}>,
        DSA<math::prime_field<uint64 {79139}>  {uint64 {4}},   uint64 {39569}>,
        DSA<math::prime_field<uint64 {79319}>  {uint64 {49}},  uint64 {39659}>,
        DSA<math::prime_field<uint64 {79559}>  {uint64 {49}},  uint64 {39779}>,
        DSA<math::prime_field<uint64 {79907}>  {uint64 {4}},   uint64 {39953}>,
        DSA<math::prime_field<uint64 {79943}>  {uint64 {25}},  uint64 {39971}>,
        DSA<math::prime_field<uint64 {79967}>  {uint64 {25}},  uint64 {39983}>,
        DSA<math::prime_field<uint64 {79979}>  {uint64 {4}},   uint64 {39989}>,
        DSA<math::prime_field<uint64 {80387}>  {uint64 {4}},   uint64 {40193}>,
        DSA<math::prime_field<uint64 {80567}>  {uint64 {25}},  uint64 {40283}>,
        DSA<math::prime_field<uint64 {80687}>  {uint64 {25}},  uint64 {40343}>,
        DSA<math::prime_field<uint64 {81119}>  {uint64 {121}}, uint64 {40559}>,
        DSA<math::prime_field<uint64 {81527}>  {uint64 {25}},  uint64 {40763}>,
        DSA<math::prime_field<uint64 {81647}>  {uint64 {25}},  uint64 {40823}>,
        DSA<math::prime_field<uint64 {81707}>  {uint64 {4}},   uint64 {40853}>,
        DSA<math::prime_field<uint64 {81899}>  {uint64 {4}},   uint64 {40949}>,
        DSA<math::prime_field<uint64 {82163}>  {uint64 {4}},   uint64 {41081}>,
        DSA<math::prime_field<uint64 {82463}>  {uint64 {25}},  uint64 {41231}>,
        DSA<math::prime_field<uint64 {82487}>  {uint64 {25}},  uint64 {41243}>,
        DSA<math::prime_field<uint64 {82763}>  {uint64 {4}},   uint64 {41381}>,
        DSA<math::prime_field<uint64 {82799}>  {uint64 {169}}, uint64 {41399}>,
        DSA<math::prime_field<uint64 {83207}>  {uint64 {25}}, uint64 {41603}>,
        DSA<math::prime_field<uint64 {83219}>  {uint64 {4}},  uint64 {41609}>,
        DSA<math::prime_field<uint64 {83243}>  {uint64 {4}},  uint64 {41621}>,
        DSA<math::prime_field<uint64 {83339}>  {uint64 {4}},  uint64 {41669}>,
        DSA<math::prime_field<uint64 {83459}>  {uint64 {4}},  uint64 {41729}>,
        DSA<math::prime_field<uint64 {83939}>  {uint64 {4}},  uint64 {41969}>,
        DSA<math::prime_field<uint64 {84047}>  {uint64 {25}}, uint64 {42023}>,
        DSA<math::prime_field<uint64 {84143}>  {uint64 {25}}, uint64 {42071}>,
        DSA<math::prime_field<uint64 {84179}>  {uint64 {4}},   uint64 {42089}>,
        DSA<math::prime_field<uint64 {84263}>  {uint64 {25}},  uint64 {42131}>,
        DSA<math::prime_field<uint64 {84443}>  {uint64 {4}},   uint64 {42221}>,
        DSA<math::prime_field<uint64 {84719}>  {uint64 {169}}, uint64 {42359}>,
        DSA<math::prime_field<uint64 {84947}>  {uint64 {4}},   uint64 {42473}>,
        DSA<math::prime_field<uint64 {85223}>  {uint64 {25}},  uint64 {42611}>,
        DSA<math::prime_field<uint64 {85439}>  {uint64 {49}},  uint64 {42719}>,
        DSA<math::prime_field<uint64 {85487}>  {uint64 {25}},  uint64 {42743}>,
        DSA<math::prime_field<uint64 {85643}>  {uint64 {4}},   uint64 {42821}>,
        DSA<math::prime_field<uint64 {85847}>  {uint64 {25}},  uint64 {42923}>,
        DSA<math::prime_field<uint64 {86027}>  {uint64 {4}},   uint64 {43013}>,
        DSA<math::prime_field<uint64 {86627}>  {uint64 {4}},   uint64 {43313}>,
        DSA<math::prime_field<uint64 {86783}>  {uint64 {25}}, uint64 {43391}>,
        DSA<math::prime_field<uint64 {87083}>  {uint64 {4}},  uint64 {43541}>,
        DSA<math::prime_field<uint64 {87299}>  {uint64 {4}},  uint64 {43649}>,
        DSA<math::prime_field<uint64 {87323}>  {uint64 {4}},  uint64 {43661}>,
        DSA<math::prime_field<uint64 {87383}>  {uint64 {25}}, uint64 {43691}>,
        DSA<math::prime_field<uint64 {87443}>  {uint64 {4}},  uint64 {43721}>,
        DSA<math::prime_field<uint64 {87587}>  {uint64 {4}},  uint64 {43793}>,
        DSA<math::prime_field<uint64 {87887}>  {uint64 {25}}, uint64 {43943}>,
        DSA<math::prime_field<uint64 {88223}>  {uint64 {25}}, uint64 {44111}>,
        DSA<math::prime_field<uint64 {88259}>  {uint64 {4}},  uint64 {44129}>,
        DSA<math::prime_field<uint64 {88379}>  {uint64 {4}},  uint64 {44189}>,
        DSA<math::prime_field<uint64 {88499}>  {uint64 {4}},  uint64 {44249}>,
        DSA<math::prime_field<uint64 {88547}>  {uint64 {4}},  uint64 {44273}>,
        DSA<math::prime_field<uint64 {89003}>  {uint64 {4}},  uint64 {44501}>,
        DSA<math::prime_field<uint64 {89087}>  {uint64 {25}}, uint64 {44543}>,
        DSA<math::prime_field<uint64 {89303}>  {uint64 {25}}, uint64 {44651}>,
        DSA<math::prime_field<uint64 {89399}>  {uint64 {49}}, uint64 {44699}>,
        DSA<math::prime_field<uint64 {89459}>  {uint64 {4}},  uint64 {44729}>,
        DSA<math::prime_field<uint64 {89759}>  {uint64 {169}}, uint64 {44879}>,
        DSA<math::prime_field<uint64 {89819}>  {uint64 {4}},   uint64 {44909}>,
        DSA<math::prime_field<uint64 {90107}>  {uint64 {4}},   uint64 {45053}>,
        DSA<math::prime_field<uint64 {90239}>  {uint64 {49}},  uint64 {45119}>,
        DSA<math::prime_field<uint64 {90263}>  {uint64 {25}},  uint64 {45131}>,
        DSA<math::prime_field<uint64 {90359}>  {uint64 {121}}, uint64 {45179}>,
        DSA<math::prime_field<uint64 {90527}>  {uint64 {25}},  uint64 {45263}>,
        DSA<math::prime_field<uint64 {90659}>  {uint64 {4}},   uint64 {45329}>,
        DSA<math::prime_field<uint64 {91139}>  {uint64 {4}},   uint64 {45569}>,
        DSA<math::prime_field<uint64 {91199}>  {uint64 {121}}, uint64 {45599}>,
        DSA<math::prime_field<uint64 {91283}>  {uint64 {4}},   uint64 {45641}>,
        DSA<math::prime_field<uint64 {91943}>  {uint64 {25}},  uint64 {45971}>,
        DSA<math::prime_field<uint64 {92363}>  {uint64 {4}},   uint64 {46181}>,
        DSA<math::prime_field<uint64 {92399}>  {uint64 {169}}, uint64 {46199}>,
        DSA<math::prime_field<uint64 {92459}>  {uint64 {4}},   uint64 {46229}>,
        DSA<math::prime_field<uint64 {92699}>  {uint64 {4}},   uint64 {46349}>,
        DSA<math::prime_field<uint64 {93047}>  {uint64 {25}},  uint64 {46523}>,
        DSA<math::prime_field<uint64 {93179}>  {uint64 {4}},   uint64 {46589}>,
        DSA<math::prime_field<uint64 {93239}>  {uint64 {121}}, uint64 {46619}>,
        DSA<math::prime_field<uint64 {93287}>  {uint64 {25}},  uint64 {46643}>,
        DSA<math::prime_field<uint64 {93383}>  {uint64 {25}},  uint64 {46691}>,
        DSA<math::prime_field<uint64 {93407}>  {uint64 {25}},  uint64 {46703}>,
        DSA<math::prime_field<uint64 {93503}>  {uint64 {25}},  uint64 {46751}>,
        DSA<math::prime_field<uint64 {94379}>  {uint64 {4}},   uint64 {47189}>,
        DSA<math::prime_field<uint64 {94559}>  {uint64 {121}}, uint64 {47279}>,
        DSA<math::prime_field<uint64 {94727}>  {uint64 {25}},  uint64 {47363}>,
        DSA<math::prime_field<uint64 {95003}>  {uint64 {4}},   uint64 {47501}>,
        DSA<math::prime_field<uint64 {95027}>  {uint64 {4}},   uint64 {47513}>,
        DSA<math::prime_field<uint64 {95087}>  {uint64 {25}},  uint64 {47543}>,
        DSA<math::prime_field<uint64 {95219}>  {uint64 {4}},   uint64 {47609}>,
        DSA<math::prime_field<uint64 {95279}>  {uint64 {49}},  uint64 {47639}>,
        DSA<math::prime_field<uint64 {95483}>  {uint64 {4}},   uint64 {47741}>,
        DSA<math::prime_field<uint64 {96059}>  {uint64 {4}},   uint64 {48029}>,
        DSA<math::prime_field<uint64 {96263}>  {uint64 {25}},  uint64 {48131}>,
        DSA<math::prime_field<uint64 {96443}>  {uint64 {4}},   uint64 {48221}>,
        DSA<math::prime_field<uint64 {96479}>  {uint64 {121}}, uint64 {48239}>,
        DSA<math::prime_field<uint64 {96827}>  {uint64 {4}},  uint64 {48413}>,
        DSA<math::prime_field<uint64 {96959}>  {uint64 {49}}, uint64 {48479}>,
        DSA<math::prime_field<uint64 {97127}>  {uint64 {25}}, uint64 {48563}>,
        DSA<math::prime_field<uint64 {97187}>  {uint64 {4}},  uint64 {48593}>,
        DSA<math::prime_field<uint64 {97463}>  {uint64 {25}}, uint64 {48731}>,
        DSA<math::prime_field<uint64 {97523}>  {uint64 {4}},  uint64 {48761}>,
        DSA<math::prime_field<uint64 {98207}>  {uint64 {25}}, uint64 {49103}>,
        DSA<math::prime_field<uint64 {98387}>  {uint64 {4}},  uint64 {49193}>,
        DSA<math::prime_field<uint64 {98507}>  {uint64 {4}},  uint64 {49253}>,
        DSA<math::prime_field<uint64 {98663}>  {uint64 {25}}, uint64 {49331}>,
        DSA<math::prime_field<uint64 {98867}>  {uint64 {4}},  uint64 {49433}>,
        DSA<math::prime_field<uint64 {98927}>  {uint64 {25}}, uint64 {49463}>,
        DSA<math::prime_field<uint64 {98963}>  {uint64 {4}},  uint64 {49481}>,
        DSA<math::prime_field<uint64 {98999}>  {uint64 {361}}, uint64 {49499}>,
        DSA<math::prime_field<uint64 {99119}>  {uint64 {121}}, uint64 {49559}>,
        DSA<math::prime_field<uint64 {99623}>  {uint64 {25}},  uint64 {49811}>,
        DSA<math::prime_field<uint64 {99707}>  {uint64 {4}},   uint64 {49853}>,
        DSA<math::prime_field<uint64 {99839}>  {uint64 {121}}, uint64 {49919}>,
        DSA<math::prime_field<uint64 {100043}> {uint64 {4}},  uint64 {50021}>,
        DSA<math::prime_field<uint64 {100103}> {uint64 {25}}, uint64 {50051}>,
        DSA<math::prime_field<uint64 {100523}> {uint64 {4}},  uint64 {50261}>,
        DSA<math::prime_field<uint64 {100547}> {uint64 {4}},  uint64 {50273}>,
        DSA<math::prime_field<uint64 {100823}> {uint64 {25}}, uint64 {50411}>,
        DSA<math::prime_field<uint64 {100847}> {uint64 {25}}, uint64 {50423}>,
        DSA<math::prime_field<uint64 {101027}> {uint64 {4}},  uint64 {50513}>,
        DSA<math::prime_field<uint64 {101183}> {uint64 {25}}, uint64 {50591}>,
        DSA<math::prime_field<uint64 {101483}> {uint64 {4}},  uint64 {50741}>,
        DSA<math::prime_field<uint64 {101747}> {uint64 {4}},  uint64 {50873}>,
        DSA<math::prime_field<uint64 {101939}> {uint64 {4}},  uint64 {50969}>,
        DSA<math::prime_field<uint64 {101987}> {uint64 {4}},  uint64 {50993}>,
        DSA<math::prime_field<uint64 {102407}> {uint64 {25}}, uint64 {51203}>,
        DSA<math::prime_field<uint64 {103007}> {uint64 {25}}, uint64 {51503}>,
        DSA<math::prime_field<uint64 {103043}> {uint64 {4}},   uint64 {51521}>,
        DSA<math::prime_field<uint64 {103079}> {uint64 {49}},  uint64 {51539}>,
        DSA<math::prime_field<uint64 {103319}> {uint64 {169}}, uint64 {51659}>,
        DSA<math::prime_field<uint64 {103787}> {uint64 {4}},   uint64 {51893}>,
        DSA<math::prime_field<uint64 {104207}> {uint64 {25}},  uint64 {52103}>,
        DSA<math::prime_field<uint64 {104243}> {uint64 {4}},   uint64 {52121}>,
        DSA<math::prime_field<uint64 {104327}> {uint64 {25}},  uint64 {52163}>,
        DSA<math::prime_field<uint64 {104579}> {uint64 {4}},   uint64 {52289}>,
        DSA<math::prime_field<uint64 {104723}> {uint64 {4}},   uint64 {52361}>,
        DSA<math::prime_field<uint64 {104759}> {uint64 {49}},  uint64 {52379}>,
        DSA<math::prime_field<uint64 {105023}> {uint64 {25}},  uint64 {52511}>,
        DSA<math::prime_field<uint64 {105107}> {uint64 {4}},   uint64 {52553}>,
        DSA<math::prime_field<uint64 {105143}> {uint64 {25}},  uint64 {52571}>,
        DSA<math::prime_field<uint64 {105167}> {uint64 {25}},  uint64 {52583}>,
        DSA<math::prime_field<uint64 {105263}> {uint64 {25}},  uint64 {52631}>,
        DSA<math::prime_field<uint64 {105467}> {uint64 {4}},   uint64 {52733}>,
        DSA<math::prime_field<uint64 {105767}> {uint64 {25}}, uint64 {52883}>,
        DSA<math::prime_field<uint64 {106103}> {uint64 {25}}, uint64 {53051}>,
        DSA<math::prime_field<uint64 {106187}> {uint64 {4}},  uint64 {53093}>,
        DSA<math::prime_field<uint64 {106619}> {uint64 {4}},  uint64 {53309}>,
        DSA<math::prime_field<uint64 {106823}> {uint64 {25}},  uint64 {53411}>,
        DSA<math::prime_field<uint64 {106907}> {uint64 {4}},   uint64 {53453}>,
        DSA<math::prime_field<uint64 {107099}> {uint64 {4}},   uint64 {53549}>,
        DSA<math::prime_field<uint64 {107183}> {uint64 {25}},  uint64 {53591}>,
        DSA<math::prime_field<uint64 {107279}> {uint64 {49}},  uint64 {53639}>,
        DSA<math::prime_field<uint64 {107699}> {uint64 {4}},   uint64 {53849}>,
        DSA<math::prime_field<uint64 {107903}> {uint64 {25}},  uint64 {53951}>,
        DSA<math::prime_field<uint64 {108023}> {uint64 {25}},  uint64 {54011}>,
        DSA<math::prime_field<uint64 {108203}> {uint64 {4}},  uint64 {54101}>,
        DSA<math::prime_field<uint64 {108503}> {uint64 {25}}, uint64 {54251}>,
        DSA<math::prime_field<uint64 {108587}> {uint64 {4}},  uint64 {54293}>,
        DSA<math::prime_field<uint64 {108803}> {uint64 {4}},  uint64 {54401}>,
        DSA<math::prime_field<uint64 {108827}> {uint64 {4}},  uint64 {54413}>,
        DSA<math::prime_field<uint64 {108887}> {uint64 {25}}, uint64 {54443}>,
        DSA<math::prime_field<uint64 {109547}> {uint64 {4}},  uint64 {54773}>,
        DSA<math::prime_field<uint64 {109883}> {uint64 {4}},  uint64 {54941}>,
        DSA<math::prime_field<uint64 {109919}> {uint64 {289}}, uint64 {54959}>,
        DSA<math::prime_field<uint64 {110459}> {uint64 {4}},   uint64 {55229}>,
        DSA<math::prime_field<uint64 {110879}> {uint64 {169}}, uint64 {55439}>,
        DSA<math::prime_field<uint64 {110939}> {uint64 {4}},   uint64 {55469}>,
        DSA<math::prime_field<uint64 {111263}> {uint64 {25}},  uint64 {55631}>,
        DSA<math::prime_field<uint64 {111323}> {uint64 {4}},   uint64 {55661}>,
        DSA<math::prime_field<uint64 {111347}> {uint64 {4}},   uint64 {55673}>,
        DSA<math::prime_field<uint64 {111443}> {uint64 {4}},   uint64 {55721}>,
        DSA<math::prime_field<uint64 {111467}> {uint64 {4}},   uint64 {55733}>,
        DSA<math::prime_field<uint64 {111599}> {uint64 {121}}, uint64 {55799}>,
        DSA<math::prime_field<uint64 {111659}> {uint64 {4}},  uint64 {55829}>,
        DSA<math::prime_field<uint64 {111779}> {uint64 {4}},  uint64 {55889}>,
        DSA<math::prime_field<uint64 {111863}> {uint64 {25}}, uint64 {55931}>,
        DSA<math::prime_field<uint64 {112019}> {uint64 {4}},  uint64 {56009}>,
        DSA<math::prime_field<uint64 {112163}> {uint64 {4}},  uint64 {56081}>,
        DSA<math::prime_field<uint64 {112199}> {uint64 {361}}, uint64 {56099}>,
        DSA<math::prime_field<uint64 {112247}> {uint64 {25}},  uint64 {56123}>,
        DSA<math::prime_field<uint64 {112787}> {uint64 {4}},   uint64 {56393}>,
        DSA<math::prime_field<uint64 {112979}> {uint64 {4}},   uint64 {56489}>,
        DSA<math::prime_field<uint64 {113039}> {uint64 {121}}, uint64 {56519}>,
        DSA<math::prime_field<uint64 {113063}> {uint64 {25}}, uint64 {56531}>,
        DSA<math::prime_field<uint64 {113327}> {uint64 {25}}, uint64 {56663}>,
        DSA<math::prime_field<uint64 {113363}> {uint64 {4}},  uint64 {56681}>,
        DSA<math::prime_field<uint64 {113567}> {uint64 {25}}, uint64 {56783}>,
        DSA<math::prime_field<uint64 {113783}> {uint64 {25}}, uint64 {56891}>,
        DSA<math::prime_field<uint64 {113819}> {uint64 {4}},   uint64 {56909}>,
        DSA<math::prime_field<uint64 {113843}> {uint64 {4}},   uint64 {56921}>,
        DSA<math::prime_field<uint64 {113903}> {uint64 {25}},  uint64 {56951}>,
        DSA<math::prime_field<uint64 {114083}> {uint64 {4}},   uint64 {57041}>,
        DSA<math::prime_field<uint64 {114299}> {uint64 {4}},   uint64 {57149}>,
        DSA<math::prime_field<uint64 {114407}> {uint64 {25}},  uint64 {57203}>,
        DSA<math::prime_field<uint64 {114659}> {uint64 {4}},   uint64 {57329}>,
        DSA<math::prime_field<uint64 {114827}> {uint64 {4}},   uint64 {57413}>,
        DSA<math::prime_field<uint64 {115547}> {uint64 {4}},   uint64 {57773}>,
        DSA<math::prime_field<uint64 {115679}> {uint64 {49}},  uint64 {57839}>,
        DSA<math::prime_field<uint64 {115763}> {uint64 {4}},   uint64 {57881}>,
        DSA<math::prime_field<uint64 {116027}> {uint64 {4}},  uint64 {58013}>,
        DSA<math::prime_field<uint64 {116099}> {uint64 {4}},  uint64 {58049}>,
        DSA<math::prime_field<uint64 {116387}> {uint64 {4}},  uint64 {58193}>,
        DSA<math::prime_field<uint64 {116423}> {uint64 {25}}, uint64 {58211}>,
        DSA<math::prime_field<uint64 {116903}> {uint64 {25}}, uint64 {58451}>,
        DSA<math::prime_field<uint64 {117023}> {uint64 {25}}, uint64 {58511}>,
        DSA<math::prime_field<uint64 {117203}> {uint64 {4}},  uint64 {58601}>,
        DSA<math::prime_field<uint64 {117779}> {uint64 {4}},  uint64 {58889}>,
        DSA<math::prime_field<uint64 {117959}> {uint64 {49}}, uint64 {58979}>,
        DSA<math::prime_field<uint64 {118043}> {uint64 {4}},  uint64 {59021}>,
        DSA<math::prime_field<uint64 {118127}> {uint64 {25}},  uint64 {59063}>,
        DSA<math::prime_field<uint64 {118247}> {uint64 {25}},  uint64 {59123}>,
        DSA<math::prime_field<uint64 {118739}> {uint64 {4}},   uint64 {59369}>,
        DSA<math::prime_field<uint64 {118787}> {uint64 {4}},   uint64 {59393}>,
        DSA<math::prime_field<uint64 {118799}> {uint64 {49}},  uint64 {59399}>,
        DSA<math::prime_field<uint64 {118907}> {uint64 {4}},   uint64 {59453}>,
        DSA<math::prime_field<uint64 {119027}> {uint64 {4}},   uint64 {59513}>,
        DSA<math::prime_field<uint64 {119243}> {uint64 {4}},   uint64 {59621}>,
        DSA<math::prime_field<uint64 {119447}> {uint64 {25}},  uint64 {59723}>,
        DSA<math::prime_field<uint64 {119759}> {uint64 {289}}, uint64 {59879}>,
        DSA<math::prime_field<uint64 {119963}> {uint64 {4}},   uint64 {59981}>,
        DSA<math::prime_field<uint64 {120167}> {uint64 {25}},  uint64 {60083}>,
        DSA<math::prime_field<uint64 {120299}> {uint64 {4}},   uint64 {60149}>,
        DSA<math::prime_field<uint64 {120503}> {uint64 {25}},  uint64 {60251}>,
        DSA<math::prime_field<uint64 {120587}> {uint64 {4}},   uint64 {60293}>,
        DSA<math::prime_field<uint64 {120767}> {uint64 {25}},  uint64 {60383}>,
        DSA<math::prime_field<uint64 {120899}> {uint64 {4}},   uint64 {60449}>,
        DSA<math::prime_field<uint64 {121019}> {uint64 {4}},   uint64 {60509}>,
        DSA<math::prime_field<uint64 {121379}> {uint64 {4}},   uint64 {60689}>,
        DSA<math::prime_field<uint64 {121439}> {uint64 {169}}, uint64 {60719}>,
        DSA<math::prime_field<uint64 {121523}> {uint64 {4}},   uint64 {60761}>,
        DSA<math::prime_field<uint64 {121547}> {uint64 {4}},   uint64 {60773}>,
        DSA<math::prime_field<uint64 {121559}> {uint64 {49}},  uint64 {60779}>,
        DSA<math::prime_field<uint64 {122663}> {uint64 {25}},  uint64 {61331}>,
        DSA<math::prime_field<uint64 {122819}> {uint64 {4}},   uint64 {61409}>,
        DSA<math::prime_field<uint64 {122939}> {uint64 {4}},   uint64 {61469}>,
        DSA<math::prime_field<uint64 {123407}> {uint64 {25}},  uint64 {61703}>,
        DSA<math::prime_field<uint64 {123503}> {uint64 {25}},  uint64 {61751}>,
        DSA<math::prime_field<uint64 {123923}> {uint64 {4}},   uint64 {61961}>,
        DSA<math::prime_field<uint64 {123983}> {uint64 {25}},  uint64 {61991}>,
        DSA<math::prime_field<uint64 {124199}> {uint64 {121}}, uint64 {62099}>,
        DSA<math::prime_field<uint64 {124343}> {uint64 {25}},  uint64 {62171}>,
        DSA<math::prime_field<uint64 {124427}> {uint64 {4}},   uint64 {62213}>,
        DSA<math::prime_field<uint64 {124703}> {uint64 {25}},  uint64 {62351}>,
        DSA<math::prime_field<uint64 {124847}> {uint64 {25}},  uint64 {62423}>,
        DSA<math::prime_field<uint64 {124919}> {uint64 {49}},  uint64 {62459}>,
        DSA<math::prime_field<uint64 {125003}> {uint64 {4}},   uint64 {62501}>,
        DSA<math::prime_field<uint64 {125183}> {uint64 {25}},  uint64 {62591}>,
        DSA<math::prime_field<uint64 {125207}> {uint64 {25}},  uint64 {62603}>,
        DSA<math::prime_field<uint64 {125507}> {uint64 {4}},   uint64 {62753}>,
        DSA<math::prime_field<uint64 {125639}> {uint64 {169}}, uint64 {62819}>,
        DSA<math::prime_field<uint64 {125963}> {uint64 {4}},   uint64 {62981}>,
        DSA<math::prime_field<uint64 {126227}> {uint64 {4}},   uint64 {63113}>,
        DSA<math::prime_field<uint64 {126359}> {uint64 {49}},  uint64 {63179}>,
        DSA<math::prime_field<uint64 {126839}> {uint64 {121}}, uint64 {63419}>,
        DSA<math::prime_field<uint64 {127343}> {uint64 {25}},  uint64 {63671}>,
        DSA<math::prime_field<uint64 {127487}> {uint64 {25}},  uint64 {63743}>,
        DSA<math::prime_field<uint64 {127607}> {uint64 {25}},  uint64 {63803}>,
        DSA<math::prime_field<uint64 {127679}> {uint64 {169}}, uint64 {63839}>,
        DSA<math::prime_field<uint64 {127727}> {uint64 {25}},  uint64 {63863}>,
        DSA<math::prime_field<uint64 {127859}> {uint64 {4}},   uint64 {63929}>,
        DSA<math::prime_field<uint64 {128603}> {uint64 {4}},   uint64 {64301}>,
        DSA<math::prime_field<uint64 {128747}> {uint64 {4}},   uint64 {64373}>,
        DSA<math::prime_field<uint64 {128879}> {uint64 {49}},  uint64 {64439}>,
        DSA<math::prime_field<uint64 {128903}> {uint64 {25}},  uint64 {64451}>,
        DSA<math::prime_field<uint64 {129419}> {uint64 {4}},   uint64 {64709}>,
        DSA<math::prime_field<uint64 {129527}> {uint64 {25}},  uint64 {64763}>,
        DSA<math::prime_field<uint64 {129587}> {uint64 {4}},   uint64 {64793}>,
        DSA<math::prime_field<uint64 {129707}> {uint64 {4}},   uint64 {64853}>,
        DSA<math::prime_field<uint64 {129803}> {uint64 {4}},   uint64 {64901}>,
        DSA<math::prime_field<uint64 {130127}> {uint64 {25}},  uint64 {65063}>,
        DSA<math::prime_field<uint64 {130199}> {uint64 {121}}, uint64 {65099}>,
        DSA<math::prime_field<uint64 {130223}> {uint64 {25}},  uint64 {65111}>,
        DSA<math::prime_field<uint64 {130259}> {uint64 {4}},   uint64 {65129}>,
        DSA<math::prime_field<uint64 {130343}> {uint64 {25}},  uint64 {65171}>,
        DSA<math::prime_field<uint64 {130367}> {uint64 {25}},  uint64 {65183}>,
        DSA<math::prime_field<uint64 {130619}> {uint64 {4}},   uint64 {65309}>,
        DSA<math::prime_field<uint64 {130787}> {uint64 {4}},   uint64 {65393}>
    >;

    template <typename X> struct DSATest;

    template <auto gen, auto order>
    struct DSATest<DSA<gen, order>> : ::testing::Test {
        using group = DSA<gen, order>;
        constexpr static const auto Generator = gen;
        constexpr static const auto Order = order;
    };

    TYPED_TEST_SUITE (DSATest, safe_17_bit_primes);

    random::std_random<std::default_random_engine> r_dsa {202020202876};

    TYPED_TEST (DSATest, DSA) {

        using G = typename TestFixture::group;
        constexpr static const auto Generator = TestFixture::Generator;
        constexpr static const auto Order = TestFixture::Order;

        test_DSA<G> (r_dsa, uint32 {5000}, uint32 {7890});
    }

}


