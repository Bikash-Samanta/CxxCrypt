#pragma once
#ifndef __cxxcrypt_core__
#define __cxxcrypt_core__ 1


#if defined(_MSC_VER)
    #define cxxcrypt_inline __forceinline
#elif defined(__GNUC__) || defined(__clang__)
    #define cxxcrypt_inline __attribute__((always_inline)) inline
#else
    #define cxxcrypt_inline inline
#endif

#define CXXCRYPT_BEGIN namespace cxxcrypt {

#define CXXCRYPT_END }


CXXCRYPT_BEGIN

enum class Error : int {
    InvalidPlainTextSize,
    InvalidCipherTextSize,
    InvalidNonceSize,
    InvalidKeySize,
    InvalidAdditionalDataSize,
    InvalidAlignmentPlainText,
    InvalidAlignmentCipherText,
    InvalidAlignmentAAD,
    AuthenticationFailed,
    CipherTextCorrupted,
    RandomFailure
};


constexpr const char* error_strings[]{
    "InvalidPlainTextSize",
    "InvalidCipherTextSize",
    "InvalidNonceSize",
    "InvalidKeySize",
    "InvalidAdditionalDataSize",
    "InvalidAlignmentPlainText",
    "InvalidAlignmentCipherText",
    "InvalidAlignmentAAD",
    "AuthenticationFailed",
    "CipherTextCorrupted",
    "RandomFailure"
};

constexpr const char* str(Error e) noexcept {
    return error_strings[static_cast<int>(e)];
}

CXXCRYPT_END


#endif
