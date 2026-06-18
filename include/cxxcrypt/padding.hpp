#pragma once

#include <string>

[[nodiscard]] inline std::string pkcs7_pad(std::string_view input) {
    constexpr std::size_t block_size = 16;

    std::string padded(input);

    std::size_t rem = padded.size() % block_size;

    if (rem == 0)
        return padded;

    std::size_t pad = block_size - rem;

    padded.append(pad, static_cast<char>(pad));

    return padded;
}

[[nodiscard]] inline std::string pkcs7_unpad(std::string_view input) {
    return std::string(input);
}