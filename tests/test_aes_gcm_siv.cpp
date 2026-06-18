#include "cxxcrypt/aes_gcm_siv.hpp"
#include "cxxcrypt/cxxcrypt_core.hpp"

#include <array>
#include <chrono>
#include <print>
#include <random>

template <std::size_t N>
inline std::array<std::byte, N> random_message() {
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    static thread_local std::uniform_int_distribution<int> dist(0, 255);

    alignas(16) std::array<std::byte, N> msg;

    for (auto& b : msg)
        b = static_cast<std::byte>(dist(gen));

    return msg;
}



int main() {
    constexpr std::size_t message_size = 16 * 100000; // 1.6 MiB
    constexpr std::size_t iterations = 1000;

    auto key = random_message<16>();
    auto aad = random_message<16 * 20>();
    auto plaintext = random_message<message_size>();

    std::array<std::byte, message_size + 32> ciphertext;
    std::array<std::byte, message_size> recovered;

    auto enc_result = cxxcrypt::aes_gcm_siv_enc(
        plaintext,
        aad,
        key,
        ciphertext
    );

    if (!enc_result) [[unlikely]] {
        std::println("{}", cxxcrypt::error_strings[static_cast<std::size_t>(enc_result.error())]);
        return 1;
    }

    auto dec_result = cxxcrypt::aes_gcm_siv_dec(
        ciphertext,
        aad,
        key,
        recovered
    );

    if (!dec_result) [[unlikely]] {
        std::println("{}", cxxcrypt::error_strings[static_cast<std::size_t>(dec_result.error())]);
        return 1;
    }

    if (plaintext == recovered)
        std::println("Encryption is working correctly");

    //---------------- Encryption benchmark ----------------

    auto enc_begin = std::chrono::steady_clock::now();

    for (std::size_t i = 0; i < iterations; ++i)
    {
        auto result = cxxcrypt::aes_gcm_siv_enc(
            plaintext,
            aad,
            key,
            ciphertext
        );

        if (!result)
        {
            std::println(stderr, "Encryption failed");
            return 1;
        }
    }

    auto enc_end = std::chrono::steady_clock::now();

    //---------------- Decryption benchmark ----------------

    auto dec_begin = std::chrono::steady_clock::now();

    for (std::size_t i = 0; i < iterations; ++i) {
        auto result = cxxcrypt::aes_gcm_siv_dec(
            ciphertext,
            aad,
            key,
            recovered
        );

        if (!result) {
            std::println(stderr, "Decryption failed");
            return 1;
        }
    }

    auto dec_end = std::chrono::steady_clock::now();

    //---------------- Verify correctness ----------------

    if (recovered != plaintext) {
        std::println(stderr, "Verification failed");
        return 1;
    }

    //---------------- Statistics ----------------

    double enc_seconds =
        std::chrono::duration<double>(enc_end - enc_begin).count();

    double dec_seconds =
        std::chrono::duration<double>(dec_end - dec_begin).count();

    double total_bytes =
        static_cast<double>(message_size) * iterations;

    double enc_gib_per_sec =
        total_bytes / enc_seconds / (1024.0 * 1024.0 * 1024.0);

    double dec_gib_per_sec =
        total_bytes / dec_seconds / (1024.0 * 1024.0 * 1024.0);

    double enc_mb_per_sec =
        total_bytes / enc_seconds / (1000.0 * 1000.0);

    double dec_mb_per_sec =
        total_bytes / dec_seconds / (1000.0 * 1000.0);

    std::println();
    std::println("AES-GCM-SIV Benchmark");
    std::println("---------------------");
    std::println("Message size : {} bytes", message_size);
    std::println("Iterations   : {}", iterations);
    std::println();

    std::println("Encryption:");
    std::println("  Time       : {:.3f} s", enc_seconds);
    std::println("  Throughput : {:.3f} MB/s ({:.3f} GiB/s)",
                 enc_mb_per_sec,
                 enc_gib_per_sec);

    std::println();

    std::println("Decryption:");
    std::println("  Time       : {:.3f} s", dec_seconds);
    std::println("  Throughput : {:.3f} MB/s ({:.3f} GiB/s)",
                 dec_mb_per_sec,
                 dec_gib_per_sec);

    std::println();
    std::println("Verification successful");
}