cmake_minimum_required(VERSION 3.20)

project(
    CxxCrypt
    VERSION 0.1.0
    DESCRIPTION "Modern C++ cryptographic library"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(examples)