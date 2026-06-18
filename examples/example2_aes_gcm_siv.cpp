#include "cxxcrypt/aes_gcm_siv.hpp"
#include "cxxcrypt/padding.hpp"
#include <print>

int main() {
    std::string key = pkcs7_pad("0123456789ABCDEF");
    std::string plaintext = pkcs7_pad("Hello AES-GCM-SIV! This is a secret message.");
    std::string aad = pkcs7_pad("Authenticated but not encrypted.");

    

    std::string ciphertext(plaintext.size() + 32, '\0');

    std::println("========== Normal encryption ==========");

    auto enc_result =
        cxxcrypt::aes_gcm_siv_enc(plaintext, aad, key, ciphertext);

    if (!enc_result) {
        std::println("Encryption failed: {}", cxxcrypt::str(enc_result.error()));
        return 1;
    }

    std::string recovered(plaintext.size(), '\0');

    auto dec_result =
        cxxcrypt::aes_gcm_siv_dec(ciphertext, aad, key, recovered);

    if (dec_result && recovered == plaintext)
        std::println("Verification successful");
    else
        std::println("Verification failed");

    std::println("plaintext : {}", plaintext);
    std::println("additional_data : {}", aad);
    std::println("ciphertext : {}", ciphertext);
    std::println("decrypted_text : {}", recovered);
    

    std::println("\n========== Tampered ciphertext ==========");

    {
        std::string corrupted = ciphertext;

        corrupted[10] ^= 1;

        std::string output(plaintext.size(), '\0');

        auto result =
            cxxcrypt::aes_gcm_siv_dec(corrupted, aad, key, output);

        if (!result)
            std::println("Attack detected ({})", cxxcrypt::str(result.error()));
        else
            std::println("Corruption was not detected");
    }


    std::println("\n========== Tampered AAD ==========");

    {
        std::string bad_aad = aad;

        bad_aad[0] ^= 1;

        std::string output(plaintext.size(), '\0');

        auto result =
            cxxcrypt::aes_gcm_siv_dec(ciphertext, bad_aad, key, output);

        if (!result)
            std::println("Attack detected ({})", cxxcrypt::str(result.error()));
        else
            std::println("Corruption was not detected");
    }


    std::println("\n========== Wrong key ==========");

    {
        std::string wrong_key = key;

        wrong_key[0] ^= 1;

        std::string output(plaintext.size(), '\0');

        auto result =
            cxxcrypt::aes_gcm_siv_dec(ciphertext, aad, wrong_key, output);

        if (!result)
            std::println("Attack detected ({})", cxxcrypt::str(result.error()));
        else
            std::println("Corruption was not detected");
    }


    std::println("\n========== Modified authentication tag ==========");

    {
        std::string bad_tag = ciphertext;

        bad_tag[bad_tag.size() - 1] ^= 1;

        std::string output(plaintext.size(), '\0');

        auto result =
            cxxcrypt::aes_gcm_siv_dec(bad_tag, aad, key, output);

        if (!result)
            std::println("Attack detected ({})", cxxcrypt::str(result.error()));
        else
            std::println("Corruption was not detected");
    }


    std::println("\n========== Truncated ciphertext ==========");

    {
        std::string short_ct = ciphertext.substr(0, ciphertext.size() - 8);

        std::string output(plaintext.size(), '\0');

        auto result =
            cxxcrypt::aes_gcm_siv_dec(short_ct, aad, key, output);

        if (!result)
            std::println("Attack detected ({})", cxxcrypt::str(result.error()));
        else
            std::println("Corruption was not detected");
    }

    return 0;
}