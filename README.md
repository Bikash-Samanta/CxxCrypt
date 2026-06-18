# CxxCrypt

> A modern, lightweight, and high-performance cryptographic library for C++.

CxxCrypt provides efficient implementations of cryptographic primitives with a clean C++ interface and hardware acceleration support. Designed for simplicity, safety, and performance, it aims to offer a modern alternative for developers who need fast and portable cryptographic functionality.

---

## Features

* SIMD-optimized implementations
* Constant-time operations where applicable
* Header-friendly modern C++ API
* Zero external dependencies
* C++26 support
* Cross-platform support

---

## Example

### AES-GCM-SIV Encryption

```cpp
#include "cxxcrypt/aes_gcm_siv.hpp"
#include "cxxcrypt/padding.hpp"

#include <print>

int main() {

    std::string key = pkcs7_pad("0123456789ABCDEF");
    std::string plaintext = pkcs7_pad("Hello AES-GCM-SIV! This is a secret message.");
    std::string aad = pkcs7_pad("Authenticated but not encrypted.");

    std::string ciphertext(plaintext.size() + 32, '\0');

    auto eresult =
        cxxcrypt::aes_gcm_siv_enc(plaintext, aad, key, ciphertext);

    if (!eresult) {
        std::println("Encryption failed: {}", cxxcrypt::str(eresult.error()));
        return 1;
    }

    std::string plaintext_out(plaintext.size(), '\0');

    auto dresult =
        cxxcrypt::aes_gcm_siv_dec(ciphertext, aad, key, plaintext_out);

    if (dresult && plaintext_out == plaintext)
        std::println("Verification successful");
    else
        std::println("Verification failed : {}", cxxcrypt::str(dresult.error()));

    std::println("plaintext : {}", pkcs7_unpad(plaintext));
    std::println("additional_data : {}", pkcs7_unpad(aad));
    std::println("ciphertext : {}", ciphertext);
    std::println("plaintext_out : {}", pkcs7_unpad(plaintext_out));

    return 0;
}
```

---

## Supported Algorithms

| Algorithm          | Status  |
| ------------------ | ------- |
| AES-128            | ✅      |
| AES-CTR            | ✅      |
| AES-GCM-SIV        | ✅      |
| POLYVAL            | ✅      |

---

## Design Goals

CxxCrypt is built with the following principles:

* **Performance first**
* **Simple and expressive API**
* **Minimal dependencies**
* **Modern C++ practices**
* **Constant-time implementations**
* **Readable and maintainable code**

---

## Build

### CMake

```bash
git clone https://github.com/Bikash-Samanta/cxxcrypt.git

cd cxxcrypt
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/examples/example1_aes_gcm_siv
./build/tests/test_aes_gcm_siv
```

---

## Benchmark

```
$ ./build/tests/test_aes_gcm_siv

Encryption is working correctly

AES-GCM-SIV Benchmark
---------------------
Message size : 1600000 bytes
Iterations   : 1000

Encryption:
  Time       : 0.247 s
  Throughput : 6476.628 MB/s (6.032 GiB/s)

Decryption:
  Time       : 0.242 s
  Throughput : 6618.757 MB/s (6.164 GiB/s)

Verification successful
```

**Platform**

* CPU: Intel/AMD x86-64 with AES-NI and PCLMULQDQ
* Compiler: GCC/Clang with `-O3`
* Build type: `Release`
* Message size: 1.6 MiB
* Iterations: 1000

> **Note:** Performance numbers are hardware-dependent and are provided for reference only.


## Requirements

* C++23 compiler
* GCC 14+
* Clang 18+
* MSVC 2022+
* Intel AES-NI capable processor

---

## Project Structure

```
cxxcrypt/
├── include/
│   └── cxxcrypt/
│       ├── aes_gcm_siv.hpp
├── src/
├── tests/
├── examples/
├── CMakeLists.txt
└── README.md
```

---

## Warning

This project is under active development.

Although great care is taken to implement algorithms correctly, cryptographic software should undergo extensive review and testing before being used in production environments.

---

<p align="center">
Built with ❤️ using Modern C++.
</p>
