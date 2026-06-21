#pragma once

#ifndef _AES_CORE_CXXCRYPT_
#define _AES_CORE_CXXCRYPT_ 1

#include "cxxcrypt_core.hpp"
#include <wmmintrin.h>
#include <ranges>


CXXCRYPT_BEGIN



template <int Rcon>
cxxcrypt_inline __m128i aes128_key_expand(__m128i key) {
    __m128i temp = _mm_aeskeygenassist_si128(key, Rcon);
    temp = _mm_shuffle_epi32(temp, _MM_SHUFFLE(3,3,3,3));

    __m128i x = key;
    x = _mm_xor_si128(x, _mm_slli_si128(x, 4));
    x = _mm_xor_si128(x, _mm_slli_si128(x, 4));
    x = _mm_xor_si128(x, _mm_slli_si128(x, 4));

    return _mm_xor_si128(x, temp);
}

cxxcrypt_inline void aes_generate_round_keys_enc(
    const __m128i master_key, __m128i round_keys_buf[11]
)
{
    round_keys_buf[0] = master_key;

    round_keys_buf[1]  = aes128_key_expand<0x01>(round_keys_buf[0]);
    round_keys_buf[2]  = aes128_key_expand<0x02>(round_keys_buf[1]);
    round_keys_buf[3]  = aes128_key_expand<0x04>(round_keys_buf[2]);
    round_keys_buf[4]  = aes128_key_expand<0x08>(round_keys_buf[3]);
    round_keys_buf[5]  = aes128_key_expand<0x10>(round_keys_buf[4]);
    round_keys_buf[6]  = aes128_key_expand<0x20>(round_keys_buf[5]);
    round_keys_buf[7]  = aes128_key_expand<0x40>(round_keys_buf[6]);
    round_keys_buf[8]  = aes128_key_expand<0x80>(round_keys_buf[7]);
    round_keys_buf[9]  = aes128_key_expand<0x1B>(round_keys_buf[8]);
    round_keys_buf[10] = aes128_key_expand<0x36>(round_keys_buf[9]);
}

cxxcrypt_inline void aes_generate_round_keys_dec(
    const __m128i aes_round_keys_enc[11], __m128i round_keys_buf[11]) 
{
    round_keys_buf[0]  = aes_round_keys_enc[10];
    round_keys_buf[1]  = _mm_aesimc_si128(aes_round_keys_enc[9]);
    round_keys_buf[2]  = _mm_aesimc_si128(aes_round_keys_enc[8]);
    round_keys_buf[3]  = _mm_aesimc_si128(aes_round_keys_enc[7]);
    round_keys_buf[4]  = _mm_aesimc_si128(aes_round_keys_enc[6]);
    round_keys_buf[5]  = _mm_aesimc_si128(aes_round_keys_enc[5]);
    round_keys_buf[6]  = _mm_aesimc_si128(aes_round_keys_enc[4]);
    round_keys_buf[7]  = _mm_aesimc_si128(aes_round_keys_enc[3]);
    round_keys_buf[8]  = _mm_aesimc_si128(aes_round_keys_enc[2]);
    round_keys_buf[9]  = _mm_aesimc_si128(aes_round_keys_enc[1]);
    round_keys_buf[10] = aes_round_keys_enc[0];
}

cxxcrypt_inline void aes_generate_round_keys_dec(
    const __m128i master_key,
    __m128i round_keys_buf[11]) 
{
    static __m128i enc[11];

    aes_generate_round_keys_enc(master_key, enc);

    round_keys_buf[0]  = enc[10];
    round_keys_buf[1]  = _mm_aesimc_si128(enc[9]);
    round_keys_buf[2]  = _mm_aesimc_si128(enc[8]);
    round_keys_buf[3]  = _mm_aesimc_si128(enc[7]);
    round_keys_buf[4]  = _mm_aesimc_si128(enc[6]);
    round_keys_buf[5]  = _mm_aesimc_si128(enc[5]);
    round_keys_buf[6]  = _mm_aesimc_si128(enc[4]);
    round_keys_buf[7]  = _mm_aesimc_si128(enc[3]);
    round_keys_buf[8]  = _mm_aesimc_si128(enc[2]);
    round_keys_buf[9]  = _mm_aesimc_si128(enc[1]);
    round_keys_buf[10] = enc[0];
}

cxxcrypt_inline __m128i aes_encrypt_block(__m128i block, const __m128i aes_round_keys_enc[11]) {
    block = _mm_xor_si128(block, aes_round_keys_enc[0]);

    for (int i = 1; i < 10; i++)
        block = _mm_aesenc_si128(block, aes_round_keys_enc[i]);

    block = _mm_aesenclast_si128(block, aes_round_keys_enc[10]);

    return block;
}

cxxcrypt_inline __m128i aes_decrypt_block(__m128i block, const __m128i aes_round_keys_dec[11]) {
    block = _mm_xor_si128(block, aes_round_keys_dec[0]);

    for (int i = 1; i < 10; i++)
        block = _mm_aesdec_si128(block, aes_round_keys_dec[i]);

    block = _mm_aesdeclast_si128(block, aes_round_keys_dec[10]);

    return block;
}


cxxcrypt_inline void aes_ctr_encrypt(
    const __m128i aes_round_keys_enc[11],
    __m128i cb,
    std::span<const __m128i> input,
    std::span<__m128i> output)
{
    static const __m128i one = _mm_set_epi32(0, 0, 0, 1);

    for (auto&& [in, ot] : std::views::zip(input, output)) {
        
        __m128i kblock = aes_encrypt_block(cb, aes_round_keys_enc);
        ot = _mm_xor_si128(in, kblock);
        cb = _mm_add_epi32(cb, one);
    }
    return;
}


cxxcrypt_inline void aes_ctr_decrypt(
    const __m128i aes_round_keys_enc[11],
    __m128i cb,
    std::span<const __m128i> input,
    std::span<__m128i> output)
{
    aes_ctr_encrypt(aes_round_keys_enc, cb, input, output);
    return;
}


CXXCRYPT_END

#endif