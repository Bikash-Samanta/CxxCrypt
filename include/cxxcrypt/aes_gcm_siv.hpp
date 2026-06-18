#pragma once
#ifndef __CxxCrypt_AES_GCM_SIV__
#define __CxxCrypt_AES_GCM_SIV__ 1

#include "cxxcrypt_core.hpp"
#include <cstddef>
#include <expected>
#include <span>



CXXCRYPT_BEGIN

using byte = std::byte;

/// Encrypts plaintext using AES-GCM-SIV.
///
/// Preconditions:
/// - plaintext must already be padded to a multiple of 16 bytes.
/// - additional_data must already be padded to a multiple of 16 bytes.
/// - key.size() must be 16 bytes.
/// - ciphertext.size() must be at least plaintext.size() + 32 bytes.
///
/// Note:
/// This function does not perform padding. Padding and unpadding are
/// the caller's responsibility.

[[nodiscard]] std::expected<std::size_t, Error> aes_gcm_siv_enc(
    std::span<byte> plaintext,
    std::span<byte> additional_data,
    std::span<byte> key,
    std::span<byte> ciphertext
);

[[nodiscard]] std::expected<std::size_t, Error> aes_gcm_siv_enc(
    std::span<char> plaintext,
    std::span<char> additional_data,
    std::span<char> key,
    std::span<char> ciphertext
);

/// Decrypts ciphertext using AES-GCM-SIV.
///
/// Preconditions:
/// - ciphertext must have been produced by aes_gcm_siv_enc().
/// - additional_data must already be padded to a multiple of 16 bytes.
/// - key.size() must be 16 bytes.
/// - plaintext.size() must be at least ciphertext.size() - 32 bytes.
///
/// Note:
/// This function does not remove padding. Unpadding is the caller's
/// responsibility.

[[nodiscard]] std::expected<std::size_t, Error> aes_gcm_siv_dec(
    std::span<byte> ciphertext,
    std::span<byte> additional_data,
    std::span<byte> key,
    std::span<byte> plaintext
);

[[nodiscard]] std::expected<std::size_t, Error> aes_gcm_siv_dec(
    std::span<char> ciphertext,
    std::span<char> additional_data,
    std::span<char> key,
    std::span<char> plaintext
);


CXXCRYPT_END

#endif