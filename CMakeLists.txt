# MIT. Build the guest ELF:
#   PATH=/opt/homebrew/opt/llvm/bin:/opt/homebrew/opt/lld/bin:$PATH \
#   cmake -S . -B build -G Ninja -DCMAKE_TOOLCHAIN_FILE=<repository-riscv64-sysroot>/toolchain.cmake \
#         -DSANDBOX_API=<contract-guest-runtime>/vendor/sandbox-api/cmake
#   cmake --build build        # writes mixer_auth.elf next to this file
cmake_minimum_required(VERSION 3.25)
project(interactor_mixer_auth_guest C CXX ASM)

set(SANDBOX_API "" CACHE PATH "the sandbox-api cmake directory (contract-guest-runtime/vendor/sandbox-api/cmake)")
if(NOT SANDBOX_API)
	message(FATAL_ERROR "set -DSANDBOX_API=<contract-guest-runtime>/vendor/sandbox-api/cmake")
endif()
set(DOWNLOAD_RUNTIME_API OFF CACHE BOOL "" FORCE)
set(SANDBOX_RISCV_EXT_V OFF CACHE BOOL "" FORCE)
set(DOUBLE_PRECISION ON CACHE BOOL "" FORCE)
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif()
add_subdirectory(${SANDBOX_API} sandbox_api)

# mbedTLS 3.6.4, pinned by hash, fetched at configure time; only the crypto the proof needs is built.
set(MBEDTLS_URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.4/mbedtls-3.6.4.tar.bz2)
set(MBEDTLS_SHA256 ec35b18a6c593cf98c3e30db8b98ff93e8940a8c4e690e66b41dfc011d678110)
set(MBEDTLS_TAR ${CMAKE_BINARY_DIR}/mbedtls-3.6.4.tar.bz2)
set(MBEDTLS_DIR ${CMAKE_BINARY_DIR}/mbedtls-3.6.4)
if(NOT EXISTS ${MBEDTLS_DIR}/library)
	file(DOWNLOAD ${MBEDTLS_URL} ${MBEDTLS_TAR} EXPECTED_HASH SHA256=${MBEDTLS_SHA256})
	file(ARCHIVE_EXTRACT INPUT ${MBEDTLS_TAR} DESTINATION ${CMAKE_BINARY_DIR})
endif()
file(GLOB MBEDTLS_SRC ${MBEDTLS_DIR}/library/*.c)
list(FILTER MBEDTLS_SRC EXCLUDE REGEX "/(ssl_|x509|pkcs7|net_sockets|debug|timing|mps_)")
add_library(mbedcrypto_guest STATIC ${MBEDTLS_SRC})
target_include_directories(mbedcrypto_guest PUBLIC ${MBEDTLS_DIR}/include PRIVATE ${MBEDTLS_DIR}/library)
target_compile_options(mbedcrypto_guest PRIVATE -O2 -fno-stack-protector -w)

add_library(mixer_auth STATIC src/mixer_auth.c)
target_link_libraries(mixer_auth PUBLIC mbedcrypto_guest)
target_compile_options(mixer_auth PRIVATE -O2 -fno-stack-protector)

add_sandbox_program(mixer_auth_guest guest/main.cpp)
set_target_properties(mixer_auth_guest PROPERTIES OUTPUT_NAME mixer_auth SUFFIX .elf RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})
target_include_directories(mixer_auth_guest PRIVATE ${SANDBOX_API}/../docker/api)
target_link_libraries(mixer_auth_guest PRIVATE mixer_auth)
