#pragma once

#include "cxxcrypt_core.hpp"

#include <span>
#include <expected>
#include <cstddef>
#include <cerrno>

#if defined(_WIN32)

    #include <windows.h>
    #include <bcrypt.h>

#elif defined(__linux__)

    #include <sys/random.h>

#elif defined(__APPLE__)

    #include <stdlib.h>

#endif

CXXCRYPT_BEGIN

[[nodiscard]] cxxcrypt_inline std::expected<void, Error> random_bytes(
    std::span<std::byte> out) noexcept
{
    if (out.empty()) [[unlikely]]
        return {};

#if defined(_WIN32)

    const NTSTATUS status = BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(out.data()),
        static_cast<ULONG>(out.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (status != STATUS_SUCCESS) [[unlikely]]
        return std::unexpected(Error::RandomFailure);

#elif defined(__linux__)

    std::size_t bytes_written = 0;

    while (bytes_written < out.size()) {
        const ssize_t n = getrandom(
            out.data() + bytes_written,
            out.size() - bytes_written,
            0
        );

        if (n > 0) [[likely]]
            bytes_written += static_cast<std::size_t>(n);

        else if (n == -1 && errno == EINTR)
            continue;

        else
            return std::unexpected(Error::RandomFailure);
    }

#elif defined(__APPLE__)

    arc4random_buf(
        out.data(),
        out.size()
    );

#else

    #error Unsupported platform

#endif

    return {};
}

CXXCRYPT_END