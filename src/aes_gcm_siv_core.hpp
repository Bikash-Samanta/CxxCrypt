#pragma once
#ifndef _AES_GCM_SIV_CORE_CXXCRYPT_
#define _AES_GCM_SIV_CORE_CXXCRYPT_ 1

#include "cxxcrypt_core.hpp"
#include "aes_core.hpp"
#include <immintrin.h>
#include <ranges>


CXXCRYPT_BEGIN

struct KeyPair {
    __m128i k1; __m128i k2;
};

inline const __m128i ctr0 = _mm_set_epi32(0,0,0,0x00000000);
inline const __m128i ctr1 = _mm_set_epi32(0,0,0,0x00000001);
inline const __m128i ctr2 = _mm_set_epi32(0,0,0,0x00000002);
inline const __m128i ctr3 = _mm_set_epi32(0,0,0,0x00000003);

inline const __m128i _mask96 = _mm_set_epi32(
    0x00000000, 0xffffffff,
    0xffffffff, 0xffffffff
);
inline const __m128i _clearb = _mm_set_epi32(
    0x7fffffff, 0xffffffff,
    0xffffffff, 0xffffffff
);
inline const __m128i _settop = _mm_set_epi32(
    0x80000000, 0, 0, 0
);

template<std::ranges::input_range R>
requires std::same_as<std::ranges::range_value_t<R>, __m128i>
cxxcrypt_inline __m128i polyval(__m128i K, R&& blocks){
    for(const auto block : blocks){
        K ^= block;
    }
    return K;
}


cxxcrypt_inline KeyPair derive_keys128(const __m128i aes_round_keys[11], const __m128i nonce) {
    __m128i B0 = _mm_or_si128(nonce, ctr0);
    __m128i B1 = _mm_or_si128(nonce, ctr1);
    __m128i B2 = _mm_or_si128(nonce, ctr2);
    __m128i B3 = _mm_or_si128(nonce, ctr3);

    __m128i C0 = aes_encrypt_block(B0, aes_round_keys);
    __m128i C1 = aes_encrypt_block(B1, aes_round_keys);
    __m128i C2 = aes_encrypt_block(B2, aes_round_keys);
    __m128i C3 = aes_encrypt_block(B3, aes_round_keys);

    __m128i AK = _mm_unpacklo_epi64(C0, C1);
    __m128i EK = _mm_unpacklo_epi64(C2, C3);

    return {AK, EK};
}


cxxcrypt_inline __m128i generate_tag(
    __m128i AK, const __m128i nonce, std::span<const __m128i> plaintext, std::span<const __m128i> additional_data)
{
    const __m128i len_block = _mm_set_epi64x(
        plaintext.size_bytes() * 8, additional_data.size_bytes() * 8
    );

    __m128i S = polyval(
        AK,
        std::views::concat(
            additional_data,
            plaintext,
            std::span{&len_block,1}
        )
    );

    S = _mm_xor_si128(S, _mm_and_si128(nonce, _mask96));
    S = _mm_and_si128(S, _clearb);

    return S;
}


cxxcrypt_inline __m128i aes_gcm_siv_encrypt(
    const __m128i round_keys_master[11],
    const __m128i nonce,
    std::span<const __m128i> additional_data,
    std::span<const __m128i> plaintext,
    std::span<__m128i> output)
{
    const auto [MAK, MEK] = derive_keys128(round_keys_master, nonce);

    __m128i S = generate_tag(MAK, nonce, plaintext, additional_data);

    alignas(16) static __m128i aes_round_keys_mek[11];

    aes_generate_round_keys_enc(MEK, aes_round_keys_mek);

    __m128i _Tag = aes_encrypt_block(S, aes_round_keys_mek);

    __m128i _Ctr = _mm_or_si128(_Tag, _settop);

    aes_ctr_encrypt(
        aes_round_keys_mek,
        _Ctr, plaintext, output
    );

    return _Tag;
}


cxxcrypt_inline bool aes_gcm_siv_decrypt(
    const __m128i round_keys_master[11],
    const __m128i nonce,
    std::span<const __m128i> additional_data,
    std::span<const __m128i> input,
    std::span<__m128i> output)
{
    const auto [MAK, MEK] = derive_keys128(round_keys_master, nonce);

    __m128i _Tag = input[0];
    __m128i _Ctr = _mm_or_si128(_Tag, _settop);

    std::span<const __m128i> ciphertext = input.subspan(1);

    alignas(16) __m128i aes_round_keys_mek_dec[11];
    aes_generate_round_keys_enc(MEK, aes_round_keys_mek_dec);

    aes_ctr_decrypt(aes_round_keys_mek_dec,_Ctr, ciphertext, output);

    __m128i S = generate_tag(MAK, nonce, output, additional_data);

    alignas(16) __m128i aes_round_keys_mek[11];
    aes_generate_round_keys_enc(MEK, aes_round_keys_mek);

    const __m128i expectedTag = aes_encrypt_block(S, aes_round_keys_mek);

    const __m128i diff = _mm_xor_si128(_Tag, expectedTag);

    return _mm_testz_si128(diff, diff);

}

CXXCRYPT_END

#endif


