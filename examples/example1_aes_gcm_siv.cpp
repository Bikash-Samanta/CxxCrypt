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