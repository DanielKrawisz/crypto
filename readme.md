# Crypto

A C++ cryptography library built on top of the [Data](#) library.

The library provides cryptographic hash functions, message authentication codes, block and stream ciphers, deterministic random bit generators, and Shamir's Secret Sharing.

## Features

<table border="0" cellpadding="0" cellspacing="0">
    <tr>
        <td colspan="2">&#183; <a href="#hash-functions">Cryptographic hash functions</a></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; MD5</td>
        <td><code>crypto/hash/MD5.hpp</code></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; SHA1</td>
        <td><code>crypto/hash/SHA1.hpp</code></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; SHA2</td>
        <td><code>crypto/hash/SHA2.hpp</code></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; RIPEMD</td>
        <td><code>crypto/hash/RIPEMD.hpp</code></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; Bitcoin</td>
        <td><code>crypto/hash/Bitcoin.hpp</code></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; SHA3</td>
        <td><code>crypto/hash/SHA3.hpp</code></td>
    </tr>
    <tr>
        <td>&#183; <a href="#password-hashing">Password hashing</a></td>
        <td><code>crypto/hash/internal.hpp</code></td>
    </tr>
    <tr>
        <td colspan="2">&nbsp;&nbsp;&nbsp;&nbsp;&#183; scrypt</td>
    </tr>
    <tr>
        <td colspan="2">&#183; <a href="#encryption">Encryption</a></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; <a href="#stream-ciphers">Stream ciphers</a></td>
        <td><code>crypto/stream/cipher.hpp</code></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; <a href="#block-ciphers">Block ciphers</a></td>
        <td><code>crypto/block.hpp</code></td>
    </tr>
    <tr>
        <td colspan="2">&#183; <a href="#message-authentication-codes">Message authentication codes</a></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; <a href="#hmac">HMAC</a></td>
        <td><code>crypto/MAC/HMAC.hpp</code></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; <a href="#cmac">CMAC</a></td>
        <td><code>crypto/MAC/CMAC.hpp</code></td>
    </tr>
    <tr>
        <td colspan="2">&#183; <a href="#key-derivation-functions">Key derivation functions</a></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; <a href="#pkcs5-pbkdf2-hmac">PKCS5_PBKDF2_HMAC</a></td>
        <td><code>crypto/PKCS5_PBKDF2_HMAC.hpp</code></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; <a href="#hkdf">HKDF</a></td>
        <td><code>crypto/HKDF.hpp</code></td>
    </tr>
    <tr>
        <td colspan="2">&#183; <a href="#deterministic-random-bit-generators">Deterministic random bit generators</a></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; <a href="#hmac-drbg">HMAC_DRBG</a></td>
        <td><code>crypto/NIST/HMAC_DRBG.hpp</code></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; <a href="#hash-drbg">Hash_DRBG</a></td>
        <td><code>crypto/NIST/Hash_DRBG.hpp</code></td>
    </tr>
    <tr>
        <td>&nbsp;&nbsp;&nbsp;&nbsp;&#183; <a href="#ctr-drbg">CTR_DRBG</a></td>
        <td><code>crypto/NIST/CTR_DRBG.hpp</code></td>
    </tr>
    <tr>
        <td>&#183; <a href="#shamirs-secret-sharing">Shamir's Secret Sharing</a></td>
        <td><code>crypto/secret_share.hpp</code></td>
    </tr>
</table>

The library is designed to integrate with the Data library and its existing data types and interfaces.

## Basic Examples

## Building and Installation

### Requirements

* A C++ compiler with C++20 support
* CMake
* ninja
* The Data library
* OpenSSL
* CryptoPP

### Configure

Clone the repository and configure a build directory:

```bash
git clone <repository>
cd crypto

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

### Build

Build the library with:

```bash
cmake --build build
```

(Use '-j10' or '--parallel' at the end to use more processors)

### Tests

If tests are enabled by the project:

```bash
ctest --test-dir build --output-on-failure
```

## Installation

Install the library with:

```bash
cmake --install build
```

To install into a custom prefix:

```bash
cmake --install build --prefix /path/to/install
```

For example:

```bash
cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/crypto

cmake --build build --parallel
cmake --install build
```

## Using the Library

Once installed, the library can be consumed through CMake:

```cmake
find_package(Crypto REQUIRED)

target_link_libraries(my_program
    PRIVATE
        Crypto::Crypto
)
```

The Data library is used by Crypto and will be made available as required by the package configuration.

## License

[License information goes here.]

## Hash Functions

Crypto provides a common interface for cryptographic hash functions, including the MD, SHA, RIPEMD, and Bitcoin hash families.

A hash function consumes an arbitrary sequence of bytes and produces a fixed-size `crypto::digest<N>`, where `N` is the digest size in bytes.

### Supported Hash Functions

The following hash functions are available:

| Family  | Functions                                                                      |
| ------- | ------------------------------------------------------------------------------ |
| CRC     | `CRC32`, `CRC32C`                                                              |
| MD5     | `MD5`                                                                          |
| SHA-1   | `SHA1`                                                                         |
| SHA-2   | `SHA2_224`, `SHA2_256`, `SHA2_384`, `SHA2_512`, `SHA2_512_224`, `SHA2_512_256` |
| SHA-3   | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`                                 |
| RIPEMD  | `RIPEMD_128`, `RIPEMD_160`, `RIPEMD_256`, `RIPEMD_320`                         |
| Bitcoin | `Bitcoin_160`, `Bitcoin_256`                                                   |

### Hashing Data

Use the hash function from the `crypto` namespace.

For example:

```cpp
#include <crypto/hash.hpp>

crypto::digest<32> dig = crypto::SHA2_256 (data);
```

The size of the returned `crypto::digest` is the output size of the hash function.

### Composable Hash Functions

Hash functions are also available as classes in the `crypto::hash` namespace.
The class-based interface is intended for composing cryptographic operations that accept hash functions as parameters.

The names correspond to the functions in the `crypto` namespace. For example:

```cpp
crypto::SHA2_256 (data);
```

has a corresponding hash function class:

```cpp
crypto::hash::SHA2_256
```

A hash function class can then be passed to another cryptographic construction that requires a hash function.

This interface allows constructions such as HMAC or NIST::Hash_DRBG to be parameterized by the hash algorithm they use.

### Incremental Hashing

For data that is not available as a single object, hashes can be calculated incrementally using `crypto::hash::writer`.

A writer is constructed with a hash function and a destination `crypto::digest`:

```cpp
crypto::digest<32> dig;

{
    crypto::hash::writer<crypto::hash::SHA2_256> writer {dig};

    writer << part1;
    writer << part2;
    writer << part3;
}
```

When the writer is destroyed, the final digest is written to the supplied `digest` object.

This makes it possible to hash a sequence of objects without first concatenating them into a single buffer.

The writer uses the same hash function classes exposed through `crypto::hash`, so it can be used wherever a particular hash construction needs to be selected at compile time.

### Digest Types

Hash functions return a `crypto::digest<N>`, which is a sequence of `N` bytes.

A digest is stored on the stack and is iterable.

Digests can be written as a hexidecimal string to an `std::ostream` via `<<`. 

```cpp
std::cout << crypto::SHA2_256 (data);
```

A digest can be written as wraw bytes to a `data::writer<byte>` via `<<`

```cpp
data::writer<byte> &write_SHA2_256 (data::writer<byte> &writer, const data::bytes &data) {
    return writer << crypto::SHA2_256 (data);
}
```
## Password Hashing

The library also provides **scrypt**, a password-hashing and password-based key derivation function.

A typical cryptographic hash function, such as SHA-256 or BLAKE2, is designed to calculate a digest quickly. This is desirable for most cryptographic applications, but it is undesirable for storing passwords: an attacker who obtains a password database can test enormous numbers of password guesses very quickly.

Password-hashing functions such as scrypt are deliberately designed to make each password guess expensive. Scrypt requires significant CPU time and memory, making large-scale password guessing substantially more difficult. The salt ensures that the same password produces different derived values when different salts are used.

Consequently, **cryptographic hashes and password hashes serve different purposes**:

* **Cryptographic hashes** such as SHA-256, SHA-512, and BLAKE2 are fast general-purpose primitives used for hashing messages, checksums, signatures, integrity mechanisms, and other cryptographic constructions.
* **Password-hashing functions** such as scrypt are deliberately expensive and are intended for passwords and other low-entropy secrets.

A password should therefore generally **not be hashed with SHA-256, SHA-512, or BLAKE2 directly**. Use a password-hashing function such as scrypt instead.

## Encryption

Crypto provides encryption and decryption functions for both stream ciphers and block ciphers.

```cpp
data::bytes encrypted = crypto::encrypt (cipher, key, plaintext);
data::bytes plaintext = crypto::decrypt (cipher, key, encrypted);
```
Both functions take a cipher, a `crypto::symmetric_key<N>`, and `data::bytes`, and return `data::bytes`.

The cipher configuration determines the algorithm, mode, padding, and any other parameters needed to perform the operation.

### Stream Ciphers

Stream ciphers are available in the `crypto::cipher::stream` namespace:

* `XChaCha20`
* `XSalsa20`
* `Salsa20`
* `HC128`
* `HC256`
* `Panama`

A stream cipher can be used directly with `crypto::encrypt` and `crypto::decrypt`:

```cpp
using Cipher = crypto::cipher::stream::XChaCha20;

Cipher cipher{/* parameters */};

data::bytes encrypted = crypto::encrypt(cipher, key, data);
data::bytes decrypted = crypto::decrypt(cipher, key, encrypted);
```

Stream ciphers operate on data as a continuous stream and therefore do not require a padding scheme.

### Block Ciphers

Block ciphers are configured using `crypto::block_cipher`.

The general form is:

```cpp
crypto::block_cipher<algorithm, mode, ...>
```

The template parameters select the underlying block cipher algorithm, the block cipher mode, and any additional parameters required by the mode or algorithm.

The supported block cipher algorithms are the AES candidates, DES, TDEA2, and TDEA3.

Block cipher modes are provided in the `crypto::cipher::block::mode` namespace:

* `ECB`
* `CBC`
* `CFB`
* `OFB`
* `CTR`

For example, an AES-based block cipher can be configured by selecting an algorithm and mode:

```cpp
using Cipher = crypto::block_cipher<
    AES_algorithm,
    crypto::cipher::block::mode::CBC
>;
```

The resulting cipher can then be passed to the encryption functions:

```cpp
Cipher cipher{/* padding */};

data::bytes encrypted = crypto::encrypt(cipher, key, data);
data::bytes decrypted = crypto::decrypt(cipher, key, encrypted);
```

The exact AES algorithm type depends on the AES candidate being selected.

#### CTR Mode

CTR mode additionally requires a byte-order parameter. It is specified as an additional template argument to `block_cipher`:

```cpp
crypto::block_cipher<
    algorithm,
    crypto::cipher::block::mode::CTR,
    endian::big
>
```

or:

```cpp
crypto::block_cipher<
    algorithm,
    crypto::cipher::block::mode::CTR,
    endian::little
>
```

#### Padding

A `block_cipher` is constructed with a padding scheme. The available padding schemes are:

* `NO_PADDING`
* `PKCS_PADDING`
* `ONE_AND_ZEROS_PADDING`

For example:

```cpp
Cipher cipher{PKCS_PADDING};
```

Padding is applied when the data does not otherwise satisfy the block-size requirements of the selected cipher mode.

`NO_PADDING` disables padding. It can only be used with block cipher modes that can operate as a virtual stream cipher, where the input does not need to be an exact multiple of the block size.

For example, modes such as CTR, CFB, and OFB can process data without requiring padding, while modes that require complete blocks cannot be used with `NO_PADDING` unless their configuration otherwise permits this behavior.

## Message Authentication Codes

Message Authentication Codes (MACs) provide a keyed cryptographic digest of a message. A MAC takes both a message and a secret symmetric key and produces a `crypto::digest<N>`.

The MAC interface is designed to be composable in the same way as the hash interface. MAC algorithms are available as direct functions in the `crypto` namespace and as composable types in `crypto::MAC`.

Currently, Crypto provides HMAC and CMAC. Additional MAC constructions, such as KMAC, can use the same interface when they are added.

### Symmetric Keys

MAC keys are represented by `crypto::symmetric_key<N>`, which is a sequence of `N` bytes.

A symmetric key is stored on the stack and is iterable. It can be written to an `std::ostream` using `<<`, where it is represented as a hexadecimal string, or to a `data::writer<byte>` using `<<`, where its raw bytes are written.

For example:

```cpp
crypto::symmetric_key<32> key;

std::cout << key;

data::writer<byte> writer;
writer << key;
```

The key is passed to the MAC along with the data being authenticated:

```cpp
crypto::digest<32> mac =
    crypto::HMAC<crypto::hash::SHA2_256>(key, data);
```

### HMAC

HMAC is available through `crypto::HMAC`, parameterized by a hash function.

For example, to calculate an HMAC-SHA-256:

```cpp
crypto::digest<32> mac =
    crypto::HMAC<crypto::hash::SHA2_256> (key, data);
```

The hash function determines the size of the resulting digest. The key is provided as a `crypto::symmetric_key<N>`.

### Composable MACs

MAC algorithms are also provided as types in the `crypto::MAC` namespace.

The composable HMAC type is:

```cpp
crypto::MAC::HMAC<hash_function>
```

For example:

```cpp
using HMAC_SHA256 = crypto::MAC::HMAC<crypto::hash::SHA2_256>;
```

This type can be passed to other cryptographic constructions that require a MAC.

The composable interface separates the MAC construction from the particular hash function it uses. For example, HMAC-SHA-256 and HMAC-SHA-512 are different instantiations of the same HMAC construction:

```cpp
using HMAC_SHA256 = crypto::MAC::HMAC<crypto::hash::SHA2_256>;
using HMAC_SHA512 = crypto::MAC::HMAC<crypto::hash::SHA2_512>;
```

### Incremental MACs

MACs can be calculated incrementally using `crypto::MAC::writer`.

A writer is constructed with a destination `crypto::digest<N>` and a symmetric key:

```cpp
crypto::digest<32> mac;

{
    crypto::MAC::writer<
        crypto::MAC::HMAC<crypto::hash::SHA2_256>
    > writer {key, mac};

    writer << header;
    writer << payload;
    writer << footer;
}
```

The writer accepts data using `<<` and feeds that data into the MAC construction. When the writer is destroyed, the final MAC is calculated and written to the supplied `crypto::digest<N>`.

The result is therefore equivalent to calculating the MAC over the concatenation of everything written to the writer:

```cpp
crypto::digest<32> mac;

{
    crypto::MAC::writer<
        crypto::MAC::HMAC<crypto::hash::SHA2_256>
    > writer{key, mac};

    writer << part1;
    writer << part2;
    writer << part3;
}
```

The resulting `mac` is the HMAC-SHA-256 of `part1 || part2 || part3`.

### MAC Interface

All MAC constructions follow the same general interface:

* A direct function in the `crypto` namespace calculates a MAC from a key and data.
* A composable MAC type is provided in `crypto::MAC`.
* `crypto::MAC::writer` provides incremental MAC calculation.
* MAC results are returned as `crypto::digest<N>`.
* Keys are represented by `crypto::symmetric_key<N>`.

HMAC is currently the only supported MAC construction. Future MAC algorithms use the same interface, allowing code that operates on MACs to remain independent of the particular MAC construction being used.

## Key Derivation Functions

### PKCS5_PBKDF2_HMAC

Crypto provides `PKCS5_PBKDF2_HMAC` for deriving a symmetric key from a password using PBKDF2 with HMAC.

The function is parameterized by the desired key size and the hash function:

```cpp
crypto::PKCS5_PBKDF2_HMAC<size, hash_function>
```

There are two overloads. The first specifies the number of PBKDF2 iterations explicitly:

```cpp
crypto::symmetric_key<size> PKCS5_PBKDF2_HMAC<size, hash_function> (
    const std::string& password,
    int iterations,
    const bytes salt = {}
);
```

The second overload specifies the desired amount of computation time instead of an explicit iteration count:

```cpp
crypto::symmetric_key<size> PKCS5_PBKDF2_HMAC<size, hash_function> (
    const std::string& password,
    std::chrono::duration<float> seconds,
    const bytes salt = {}
);
```

Both overloads return a `crypto::symmetric_key<size>`. The salt is optional and defaults to an empty byte
sequence but ordinarily you would want a unique and unpredictible salt.

### HKDF

HKDF is a key derivation function based on HMAC. It is intended for deriving cryptographic keys and other pseudorandom values from existing secret key material.

HKDF consists of two separate operations.

Extract converts input keying material into a fixed-size pseudorandom key (PRK). The PRK size is equal to the digest size of the underlying hash:

PRK = HMAC(salt, IKM)

A salt may be supplied explicitly, or omitted. When no salt is supplied, HKDF uses a salt consisting of DigestSize zero bytes.

Expand uses the PRK to generate the requested amount of output, optionally incorporating application-specific context through info:

T(1) = HMAC(PRK, T(0) || info || 0x01)
T(2) = HMAC(PRK, T(1) || info || 0x02)
...

The output length is selected when the HKDF operation is created. HKDF can produce a variable number of bytes, but unlike an XOF it has a maximum output size of 255 * DigestSize.

HKDF can be used as a reader, making it convenient to derive several values from one expansion:

HKDF<SHA256> hkdf {ikm, info, 64};

hkdf >> key1;
hkdf >> key2;

The two keys consume consecutive portions of the derived output.

HKDF is a key derivation function, not a source of entropy. Its input keying material must already contain sufficient entropy for the security level required by the application.

## Random Number Generators

Crypto provides cryptographically secure deterministic random bit generators (DRBGs) based on the constructions specified by NIST SP 800-90A.

All random number generators derive from `data::random::source`, allowing them to be used anywhere a Data random source is expected.

The NIST generators are provided in the `crypto::NIST` namespace:

* `Hash_DRBG`
* `HMAC_DRBG`
* `CTR_DRBG`

### Generating Random Data

All generators provide a `generate` function that writes random bytes into a caller-provided buffer:

```cpp
void generate(
    byte *b,
    size_t x,
    byte_slice additional = {}
);
```

For example:

```cpp
byte buffer[32];

rng.generate(buffer, sizeof(buffer));
```

The optional `additional` parameter supplies additional input to the generation operation as specified by the particular NIST construction.

Because the generators derive from `data::random::source`, they also implement the `read` interface:

```cpp
void read(byte *b, size_t x);
```

`read` generates the requested number of bytes and is equivalent to calling `generate` without additional input:

```cpp
rng.read(buffer, sizeof(buffer));
```

### Reseeding

All NIST generators support reseeding with new entropy:

```cpp
void reseed(
    byte_slice entropy,
    byte_slice additional
);
```

An overload accepting only entropy is also provided:

```cpp
void reseed(byte_slice entropy);
```

The single-argument form is equivalent to supplying an empty `additional` input.

```cpp
rng.reseed(entropy);
```

or:

```cpp
rng.reseed(entropy, additional);
```

Reseeding incorporates fresh entropy into the generator's internal state. The optional additional input can be used when the application has additional data that should be incorporated into the reseeding operation.

## NIST Hash_DRBG

`crypto::NIST::Hash_DRBG` implements the NIST Hash_DRBG construction and is parameterized by its hash function:

```cpp
crypto::NIST::Hash_DRBG<hash>
```

The hash function must be one of the approved hash functions specified by NIST SP 800-90A.

For example:

```cpp
crypto::NIST::Hash_DRBG<crypto::hash::SHA2_256> rng(entropy);
```

Random data can then be generated using either `generate` or the inherited random-source interface:

```cpp
byte buffer[32];

rng.generate(buffer, sizeof(buffer));
```

### NIST HMAC_DRBG

`crypto::NIST::HMAC_DRBG` implements the NIST HMAC_DRBG construction and is parameterized by its hash function:

```cpp
crypto::NIST::HMAC_DRBG<hash>
```

The hash function must be one of the approved hash functions specified by NIST SP 800-90A.

For example:

```cpp
crypto::NIST::HMAC_DRBG<crypto::hash::SHA2_256> rng(entropy);
```

The generator can then be used as a `data::random::source`:

```cpp
byte buffer[32];

rng.read(buffer, sizeof(buffer));
```

## NIST CTR_DRBG

`crypto::NIST::CTR_DRBG` implements the NIST CTR_DRBG construction.

Its template parameters are:

```cpp
crypto::NIST::CTR_DRBG<
    key_size,
    algorithm,
    use_df = true,
    order = endian::big
>
```

The parameters select the size of the internal key, the block cipher algorithm, whether the derivation function is used, and the byte order.

The algorithm must be one of the algorithms approved for CTR_DRBG by NIST SP 800-90A. Crypto currently supports:

* AES
* TDEA3

For example, a CTR_DRBG using AES can be configured as:

```cpp
crypto::NIST::CTR_DRBG<
    key_size,
    AES_algorithm
> rng(entropy);
```

The `use_df` parameter controls whether the derivation function is used. It defaults to `true`.

The `order` parameter specifies byte order and defaults to `endian::big`:

```cpp
crypto::NIST::CTR_DRBG<
    key_size,
    AES_algorithm,
    true,
    endian::little
>
```

The selected algorithm must satisfy the requirements of CTR_DRBG, and only approved algorithms can be used.

### Common Random Source Interface

Because all of the generators derive from `data::random::source`, applications can use them through the common random-source interface without depending on the particular DRBG construction.

For example:

```cpp
data::random::source& source = rng;

byte buffer[64];
source.read(buffer, sizeof(buffer));
```

This allows the choice of random generator to be separated from code that consumes random data.


### HMAC_DRBG example

```cpp
#include <crypto/hmac_drbg.hpp>

crypto::HMAC_DRBG<crypto::SHA256> rng(seed);

auto random_data = rng.generate(32);
```

The Hash_DRBG and CTR_DRBG implementations provide equivalent deterministic random-generation facilities using their respective construction.

## Shamir's Secret Sharing

Shamir's Secret Sharing allows a secret to be divided into multiple shares such that a configurable threshold number of shares is required to reconstruct the original secret.

For example, a secret can be divided into five shares with any three shares required for recovery:

```cpp
#include <crypto/shamir.hpp>

auto shares = crypto::shamir::split(secret, 3, 5);

auto recovered = crypto::shamir::combine({
    shares[0],
    shares[2],
    shares[4]
});
```

No fewer than the configured threshold of shares can reconstruct the secret.

