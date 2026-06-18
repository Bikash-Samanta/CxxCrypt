#include "cxxcrypt_core.hpp"
#include "cxxcrypt_rand.hpp"
#include "aes_gcm_siv_core.hpp"
#include "aes_core.hpp"
#include "aes_gcm_siv.hpp"

#include <cstdlib>
#include <expected>
#include <immintrin.h>
#include <cstdint>


CXXCRYPT_BEGIN


[[nodiscard]] std::expected<void, Error> validate_aes_gcm_siv128_inputs(
    std::span<const byte> plaintext,
    std::span<const byte> additional_data,
    std::span<const byte> key,
    std::span<const byte> ciphertext) noexcept 
{
    if ((reinterpret_cast<std::uintptr_t>(plaintext.data()) & 15) != 0) [[unlikely]]
        return std::unexpected(Error::InvalidAlignmentPlainText);

    if ((reinterpret_cast<std::uintptr_t>(additional_data.data()) & 15) != 0) [[unlikely]]
        return std::unexpected(Error::InvalidAlignmentAAD);
    
    if ((reinterpret_cast<std::uintptr_t>(ciphertext.data()) & 15) != 0) [[unlikely]]
        return std::unexpected(Error::InvalidAlignmentCipherText);

    if (plaintext.empty() || plaintext.size() % 16 != 0) [[unlikely]]
        return std::unexpected(Error::InvalidPlainTextSize);

    if (additional_data.size() % 16 != 0) [[unlikely]] 
        return std::unexpected(Error::InvalidAdditionalDataSize);

    if (key.size() != 16) [[unlikely]]
        return std::unexpected(Error::InvalidKeySize);

    if (ciphertext.size() < (plaintext.size() + 16)) [[unlikely]]
        return std::unexpected(Error::InvalidCipherTextSize);

    return {};
}

[[nodiscard]] cxxcrypt_inline std::expected<__m128i, Error> random_nonce() {
    alignas(16) static std::byte nonce[16]{};
    auto result = random_bytes({nonce + 4, 12});
    if(!result) [[unlikely]] 
        return std::unexpected(result.error());
    return _mm_load_si128(reinterpret_cast<const __m128i*>(nonce));
}


[[nodiscard]] std::expected<std::size_t, Error> aes_gcm_siv_enc(
    std::span<byte> plaintext,
    std::span<byte> additional_data,
    std::span<byte> key,
    std::span<byte> ciphertext)
{

    auto validation = validate_aes_gcm_siv128_inputs(
        plaintext, additional_data, key, ciphertext
    );

    if (!validation) [[unlikely]] {
        return std::unexpected(validation.error());
    }
        
    __m128i key_128 =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data()));
        
    auto nonce_result = random_nonce();

    if (!nonce_result) [[unlikely]]
        return std::unexpected(nonce_result.error());

    __m128i nonce_128 = *nonce_result;
    
    std::span<__m128i> pt{
        reinterpret_cast<__m128i*>(plaintext.data()),
        plaintext.size() / 16
    };
    
    std::span<__m128i> aad{
        reinterpret_cast<__m128i*>(additional_data.data()),
        additional_data.size() / 16
    };

    __m128i* ctptr = reinterpret_cast<__m128i*>(ciphertext.data());
    
    std::span<__m128i> ct{
        ctptr + 2,
        ciphertext.size() / 16
    };
    
    alignas(16) __m128i round_keys[11];

    aes_generate_round_keys_enc(key_128, round_keys);

    __m128i _Tag = cxxcrypt::aes_gcm_siv_encrypt(
        round_keys,
        nonce_128,
        aad,
        pt,
        ct
    );

    ctptr[0] = nonce_128;
    ctptr[1] = _Tag;

    return plaintext.size() + sizeof(__m128i) * 2;

}

[[nodiscard]] std::expected<std::size_t, Error> aes_gcm_siv_dec(
    std::span<byte> ciphertext,
    std::span<byte> additional_data,
    std::span<byte> key,
    std::span<byte> plaintext)
{

    auto validation = validate_aes_gcm_siv128_inputs(
        plaintext, additional_data, key, ciphertext
    );

    if (!validation) [[unlikely]] {
        return std::unexpected(validation.error());
    }
        
    __m128i key_128 =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data()));

        
    std::span<__m128i> aad{
        reinterpret_cast<__m128i*>(additional_data.data()),
        additional_data.size() / 16
    };
        
    std::span<__m128i> pt{
        reinterpret_cast<__m128i*>(plaintext.data()),
        plaintext.size() / 16
    };

    __m128i* ctptr = reinterpret_cast<__m128i*>(ciphertext.data());

    __m128i nonce_128 = ctptr[0];

    std::span<__m128i> ct{
        ctptr + 1,
        ciphertext.size() / 16
    };

    alignas(16) __m128i round_keys[11];
        
    aes_generate_round_keys_enc(key_128, round_keys);
    

    bool success = cxxcrypt::aes_gcm_siv_decrypt(
        round_keys,
        nonce_128,
        aad,
        ct,
        pt
    );

    if (!success) [[unlikely]]
        return std::unexpected(Error::AuthenticationFailed);

    return ciphertext.size() - 2 * sizeof(__m128i);

}


[[nodiscard]] std::expected<std::size_t, Error> aes_gcm_siv_enc(
    std::span<char> plaintext,
    std::span<char> additional_data,
    std::span<char> key,
    std::span<char> ciphertext
)
{
    return aes_gcm_siv_enc(
        std::as_writable_bytes(plaintext),
        std::as_writable_bytes(additional_data),
        std::as_writable_bytes(key),
        std::as_writable_bytes(ciphertext)
    );
}

[[nodiscard]] std::expected<std::size_t, Error> aes_gcm_siv_dec(
    std::span<char> ciphertext,
    std::span<char> additional_data,
    std::span<char> key,
    std::span<char> plaintext
)
{
    return aes_gcm_siv_dec(
        std::as_writable_bytes(ciphertext),
        std::as_writable_bytes(additional_data),
        std::as_writable_bytes(key),
        std::as_writable_bytes(plaintext)
    );
}



CXXCRYPT_END
