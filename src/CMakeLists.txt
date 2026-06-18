file(GLOB_RECURSE CXXCRYPT_SOURCES "*.cpp")

add_library(CxxCrypt ${CXXCRYPT_SOURCES})

target_include_directories(CxxCrypt
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include

    PRIVATE
        ${PROJECT_SOURCE_DIR}/include/cxxcrypt
)

target_compile_options(CxxCrypt PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -maes
    -mpclmul
    -msse4.1
    -Wno-ignored-attributes
)