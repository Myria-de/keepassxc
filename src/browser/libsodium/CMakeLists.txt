#
# Copyright (c) 2017
# Sami Vänttinen
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#


project(libsodium LANGUAGES C CXX ASM)
INCLUDE(CheckCCompilerFlag)

OPTION(LIBSODIUM_BUILD_SHARED_LIBRARIES "Build the library dynamically (ON/TRUE) or statically (OFF/FALSE).")
OPTION(ENABLE_BLOCKING_RANDOM           "Enable this switch only if /dev/urandom is totally broken on the target platform.")
OPTION(ENABLE_MINIMAL_BUILD             "Only compile the minimum set of functions required for the high-level API.")
OPTION(ENABLE_TESTS                     "Enable testing.")
OPTION(DISABLE_ASM                      "Disable AMD64 assembly implementations.")
OPTION(DISABLE_PIE                      "Do not produce position independent executables.")
OPTION(DISABLE_SSP                      "Do not compile with -fstack-protector.")
OPTION(DISABLE_CPM                      "Do not use CPM module")

SET(VERSION 1.0.13)
SET(SODIUM_LIBRARY_VERSION_MAJOR 9)
SET(SODIUM_LIBRARY_VERSION_MINOR 4)
SET(DLL_VERSION 8)
SET(SODIUM_LIBRARY_VERSION "20:1:2")

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/include/sodium/version.h.in #${CMAKE_CURRENT_BINARY_DIR}/include/sodium/version.h)
${CMAKE_CURRENT_SOURCE_DIR}/include/sodium/version.h)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include/sodium)
#For version.h.in to version.h
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/include/sodium)

#----------------------------------------------------------
###################### SYSTEM CHECKS ######################
#----------------------------------------------------------

MESSAGE("---------------- PERFORMING SYSTEM CHECKS. ----------------")

# MSVC does not provide inline in C (only CXX)
IF(MSVC)
    ADD_DEFINITIONS("-Dinline=__inline")
ENDIF(MSVC)

#Endianess check
INCLUDE(TestBigEndian)
TEST_BIG_ENDIAN(BIG_ENDIAN)

IF(${BIG_ENDIAN})
    SET(IS_BIG_ENDIAN ON)
    ADD_DEFINIIONS("-DNATIVE_BIG_ENDIAN=1")
    MESSAGE("System is in Big Endian.")
ELSE(${BIG_ENDIAN})
    SET(IS_BIG_ENDIAN OFF)
    ADD_DEFINITIONS("-DNATIVE_LITTLE_ENDIAN=1")
    MESSAGE("System is in Little Endian.")
ENDIF(${BIG_ENDIAN})


IF(EMSCRIPTEN)
    SET(DISABLE_ASM ON)
    MESSAGE("Compiling to javascript, disabling asm implementations.")
ENDIF()


IF(MSYS OR MINGW OR CYGWIN)
    SET(DISABLE_PIE ON)
ENDIF()


#TI mode check
IF(${IS_BIGENDIAN})
    TRY_COMPILE(HAVE_TI_MODE_COMPILE ${CMAKE_CURRENT_BINARY_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/test/HAVE_TI_MODE.c COMPILE_DEFINITIONS -DNATIVE_BIG_ENDIAN=1)
ELSE(${IS_BIGENDIAN})
    TRY_COMPILE(HAVE_TI_MODE_COMPILE ${CMAKE_CURRENT_BINARY_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/test/HAVE_TI_MODE.c COMPILE_DEFINITIONS -DNATIVE_LITTLE_ENDIAN=1)
ENDIF(${IS_BIGENDIAN})

IF(HAVE_TI_MODE_COMPILE)

    SET(libsodium_HEADERS ${libsodium_HEADERS}
        crypto_scalarmult/curve25519/donna_c64/curve25519_donna_c64.h
    )

    SET(libsodium_SOURCE ${libsodium_SOURCE}
        crypto_scalarmult/curve25519/donna_c64/curve25519_donna_c64.c
    )

    ADD_DEFINITIONS(-DHAVE_TI_MODE)

    MESSAGE("Gcc TI Mode is available.")

ELSE(HAVE_TI_MODE_COMPILE)

    SET(libsodium_HEADERS ${libsodium_HEADERS}
        crypto_scalarmult/curve25519/ref10/x25519_ref10.h
    )

    SET(libsodium_SOURCE ${libsodium_SOURCE}
        crypto_scalarmult/curve25519/ref10/x25519_ref10.c
    )

    MESSAGE("Gcc TI Mode is not available.")

ENDIF(HAVE_TI_MODE_COMPILE)

#Check if weak symbols are supported.
TRY_COMPILE(HAVE_WEAK_SYMBOLS_COMPILE ${CMAKE_CURRENT_BINARY_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/test/HAVE_WEAK_SYMBOLS.c)
IF(HAVE_WEAK_SYMBOLS_COMPILE)
    ADD_DEFINITIONS("-DHAVE_WEAK_SYMBOLS")
    MESSAGE("Weak Symbols are supported.")
ELSE(HAVE_WEAK_SYMBOLS_COMPILE)
    MESSAGE("Weak Symbols are not supported.")
    SET(TEST ON)
ENDIF(HAVE_WEAK_SYMBOLS_COMPILE)

#Is __STDC_LIMIT_MACROS needed check.
TRY_COMPILE(IS_STDC_LIMIT_MACROS_NEEDED_COMPILE ${CMAKE_CURRENT_BINARY_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/test/IS_STDC_LIMIT_MACROS_NEEDED.c)
IF(IS_STDC_LIMIT_MACROS_NEEDED_COMPILE)
    #If this works then we dont need to define __STDC_LIMIT_MACROS and __STDC_CONSTANT_MACROS.
    MESSAGE("__STDC_LIMIT_MACROS and __STDC_CONSTANT_MACROS not needed.")
ELSE(IS_STDC_LIMIT_MACROS_NEEDED_COMPILE)
    ADD_DEFINITIONS("-D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS")
    MESSAGE("__STDC_LIMIT_MACROS and __STDC_CONSTANT_MACROS is needed and was added to the definitions.")
ENDIF(IS_STDC_LIMIT_MACROS_NEEDED_COMPILE)


#Is there a functionnal ASM compiler
SET(CMAKE_ASM_SOURCE_FILE_EXTENSIONS "s;S")
ENABLE_LANGUAGE(ASM)

IF(CMAKE_ASM_COMPILER_WORKS)
    SET(ASSEMBLER_AVAILABLE ON)
    MESSAGE("An ASM compiler has been found and is functionnal.")
ELSE(CMAKE_ASM_COMPILER_WORKS)
    SET(ASSEMBLER_AVAILABLE OFF)
    MESSAGE(FATAL "An ASM compiler has not been found or is not functionnal.")
ENDIF(CMAKE_ASM_COMPILER_WORKS)


#cpuid instruction check
TRY_COMPILE(IS_CPUID_INSTRUCTION_AVAILABLE_COMPILE ${CMAKE_CURRENT_BINARY_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/test/HAVE_CPUID.c)
IF(IS_CPUID_INSTRUCTION_AVAILABLE_COMPILE)
    SET(IS_CPUID_INSTRUCTION_AVAILABLE ON)
    ADD_DEFINITIONS("-DHAVE_CPUID")
    MESSAGE("Cpuid instruction is available.")
ELSE(IS_CPUID_INSTRUCTION_AVAILABLE_COMPILE)
    SET(IS_CPUID_INSTRUCTION_AVAILABLE OFF)
    MESSAGE("Cpuid instruction is not available.")
ENDIF(IS_CPUID_INSTRUCTION_AVAILABLE_COMPILE)

#Have AMD64 ASM check
IF(DISABLE_ASM)

    MESSAGE("AMD64 ASM implementations have been disabled.")

    SET(libsodium_HEADERS ${libsodium_HEADERS}
        crypto_stream/salsa20/ref/salsa20_ref.h
    )

    SET(libsodium_SOURCE ${libsodium_SOURCE}
        crypto_stream/salsa20/ref/salsa20_ref.c
    )

ELSE(DISABLE_ASM)

    IF(ASSEMBLER_AVAILABLE)

        TRY_COMPILE(HAVE_AMD64_ASM_COMPILE ${CMAKE_CURRENT_BINARY_DIR}/build ${CMAKE_CURRENT_SOURCE_DIR}/test/HAVE_AMD64_ASM.c)
        IF(HAVE_AMD64_ASM_COMPILE)
            ADD_DEFINITIONS(-DHAVE_AMD64_ASM=1)

            SET(libsodium_HEADERS ${libsodium_HEADERS}
                crypto_stream/salsa20/xmm6/salsa20_xmm6.h
            )

            SET(libsodium_SOURCE ${libsodium_SOURCE}
                crypto_stream/salsa20/xmm6/salsa20_xmm6-asm.S
            )

            MESSAGE("AMD64 ASM is available.")

        ELSE(HAVE_AMD64_ASM_COMPILE)

            SET(libsodium_HEADERS ${libsodium_HEADERS}
                crypto_stream/salsa20/ref/salsa20_ref.h
            )

            SET(libsodium_SOURCE ${libsodium_SOURCE}
                crypto_stream/salsa20/ref/salsa20_ref.c
            )

            MESSAGE("AMD64 ASM is not available.")

        ENDIF(HAVE_AMD64_ASM_COMPILE)
    ENDIF(ASSEMBLER_AVAILABLE)
ENDIF(DISABLE_ASM)


MESSAGE("---------------- DONE WITH SYSTEM CHECKS. -----------------")
MESSAGE("                                                           ")

#Compiler flag check macro definition.
MACRO(CHECK_COMPILER_FLAG)

    SET(FLAG "-${ARGV0}")
    SET(IS_${ARGV0}_AVAILABLE)

    CHECK_C_COMPILER_FLAG(${FLAG} IS_${ARGV0}_AVAILABLE)

    IF(IS_${ARGV0}_AVAILABLE)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
        MESSAGE("Checking if ${FLAG} is available... It is available.")
    ELSE(IS_${ARGV0}_AVAILABLE)
        MESSAGE("Checking if ${FLAG} is available... It is not available.")
    ENDIF(IS_${ARGV0}_AVAILABLE)

ENDMACRO(CHECK_COMPILER_FLAG)

MESSAGE("------------- PERFORMING COMPILER FLAG CHECKS. ------------")


#Check if debug mode is active
IF(CMAKE_BUILD_TYPE MATCHES Debug)
    MESSAGE("-- Debug build enabled. --")
    ADD_DEFINITIONS("-DDEBUG=1")
    CHECK_COMPILER_FLAG(O)
    CHECK_COMPILER_FLAG(g3)
ELSE(CMAKE_BUILD_TYPE MATCHES Debug)
    MESSAGE("-- Release build enabled. --")
    CHECK_COMPILER_FLAG(O3)
ENDIF(CMAKE_BUILD_TYPE MATCHES Debug)

#Check if -std=c99 is available.
CHECK_COMPILER_FLAG(std=c99)

#Check if -D_FORTIFY_SOURCE=2 is available.
CHECK_COMPILER_FLAG(D_FORTIFY_SOURCE=2)

#Check if clang and if -Wno-unknown-warning-option is available.
IF("${CMAKE_C_COMPILER_ID}" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    CHECK_COMPILER_FLAG(Wno-unknown-warning-option)
ENDIF()

IF(NOT (MSYS OR MINGW OR CYGWIN))
    #Check if -fPIC is available.
    CHECK_COMPILER_FLAG(fPIC)
ELSE(NOT (MSYS OR MINGW OR CYGWIN))
    CHECK_COMPILER_FLAG(Wl,--dynamicbase)
    CHECK_COMPILER_FLAG(Wl,--nxcompat)
ENDIF(NOT (MSYS OR MINGW OR CYGWIN))

#Check if -fPIE is available.
IF(NOT DISABLE_PIE)
    CHECK_COMPILER_FLAG(fPIE)
ENDIF(NOT DISABLE_PIE)

#Check if -Wall is available.
CHECK_COMPILER_FLAG(Wall)

#Check if -Wextra is available.
CHECK_COMPILER_FLAG(Wextra)

#Check if -fvisibility=hidden is available
CHECK_COMPILER_FLAG(fvisibility=hidden)

#Check if -fno-strict-aliasing is available.
CHECK_COMPILER_FLAG(fno-strict-aliasing)

#Check if -fno-strict-overflow is available.
CHECK_COMPILER_FLAG(fno-strict-overflow)
IF(NOT IS_fno-strict-overflow_AVAILABLE)
    #If -fno-strict-overflow is not available, try with -fwrapv.
    CHECK_COMPILER_FLAG(fwrapv)
ENDIF()

IF(NOT DISABLE_SSP)
    #Check if -fstack-protector is available.
    CHECK_COMPILER_FLAG(fstack-protector)
ENDIF(NOT DISABLE_SSP)

#Check if -Winit-self is available.
CHECK_COMPILER_FLAG(Winit-self)

#Check if -Wwrite-strings is available.
CHECK_COMPILER_FLAG(Wwrite-strings)

#Check if -Wdiv-by-zero is available.
CHECK_COMPILER_FLAG(Wdiv-by-zero)

#Check if -Wsometimes-uninitialized is available.
CHECK_COMPILER_FLAG(Wsometimes-uninitialized)

#Check if -Wbad-function-cast is available.
CHECK_COMPILER_FLAG(Wbad-function-cast)

#Check if -Wcast-align is available.
CHECK_COMPILER_FLAG(Wcast-align)

#Check if -Wcast-qual is available.
CHECK_COMPILER_FLAG(Wcast-qual)

#Check if -Wchar-subscripts is available.
CHECK_COMPILER_FLAG(Wchar-subscripts)

#Check if -Wcomment is available.
CHECK_COMPILER_FLAG(Wcomment)

#Check if -Wfloat-equal is available.
CHECK_COMPILER_FLAG(Wfloat-equal)

#Check if -Wformat=2 is available.
CHECK_COMPILER_FLAG(Wformat=2)

#Check if -Wimplicit is available.
CHECK_COMPILER_FLAG(Wimplicit)

#Check if -Wmissing-declarations is available.
CHECK_COMPILER_FLAG(Wmissing-declarations)

#Check if -Wmissing-prototypes is available.
CHECK_COMPILER_FLAG(Wmissing-prototypes)

#Check if -Wnormalized=id is available.
CHECK_COMPILER_FLAG(Wnormalized=id)

#Check if -Woverride-init is available.
CHECK_COMPILER_FLAG(Woverride-init)

#Check if -Wparentheses is available.
CHECK_COMPILER_FLAG(Wparentheses)

#Check if -Wpointer-arith is available.
CHECK_COMPILER_FLAG(Wpointer-arith)

#Check if -Wredundant-decls is available.
CHECK_COMPILER_FLAG(Wredundant-decls)

#Check if -Wstrict-prototypes is available.
CHECK_COMPILER_FLAG(Wstrict-prototypes)

#Check if -Wswitch-enum is available.
CHECK_COMPILER_FLAG(Wswitch-enum)

#Check if -Wvariable-dec is available.
CHECK_COMPILER_FLAG(Wvariable-decl)

#Check if -Wl,-z,relro is available.
CHECK_COMPILER_FLAG(Wl,-z,relro)

#Check if -Wl,-z,now is available.
CHECK_COMPILER_FLAG(Wl,-z,now)

#Check if -Wl,-z,noexecstack is available.
CHECK_COMPILER_FLAG(Wl,-z,noexecstack)

#Check if -Wl,--verbose is available and enable it.
#CHECK_COMPILER_FLAG(Wl,--verbose)


MESSAGE("------------- DONE WITH COMPILER FLAG CHECKS. -------------")
MESSAGE("                                                           ")

SET(libsodium_HEADERS ${libsodium_HEADERS}
    crypto_sign/ed25519/ref10/ed25519_ref10.h
    crypto_pwhash/argon2/argon2.h
    crypto_pwhash/argon2/blake2b-long.h
    crypto_pwhash/argon2/blamka-round-ref.h
    crypto_pwhash/argon2/argon2-core.h
    crypto_pwhash/argon2/blamka-round-ssse3.h
    crypto_pwhash/argon2/argon2-encoding.h
    crypto_pwhash/scryptsalsa208sha256/crypto_scrypt.h
    crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.h
    include/sodium/runtime.h
    include/sodium/crypto_stream_salsa208.h
    include/sodium/crypto_stream_aes128ctr.h
    include/sodium/crypto_sign_ed25519.h
    include/sodium/crypto_box_curve25519xchacha20poly1305.h
    include/sodium/crypto_verify_64.h
    include/sodium/crypto_pwhash.h
    include/sodium/crypto_kx.h
    include/sodium/core.h
    include/sodium/crypto_aead_chacha20poly1305.h
    include/sodium/crypto_kdf_blake2b.h
    include/sodium/crypto_auth_hmacsha256.h
    include/sodium/crypto_pwhash_scryptsalsa208sha256.h
    include/sodium/crypto_auth_hmacsha512.h
    include/sodium/crypto_stream_chacha20.h
    include/sodium/randombytes.h
    include/sodium/randombytes_nativeclient.h
    include/sodium/crypto_hash_sha512.h
    include/sodium/crypto_stream_xsalsa20.h
    include/sodium/crypto_kdf.h
    include/sodium/crypto_shorthash_siphash24.h
    include/sodium/crypto_verify_16.h
    include/sodium/crypto_stream_xchacha20.h
    include/sodium/crypto_auth_hmacsha512256.h
    include/sodium/crypto_generichash.h
    include/sodium/crypto_scalarmult.h
    include/sodium/crypto_sign.h
    include/sodium/crypto_secretbox_xchacha20poly1305.h
    include/sodium/crypto_secretbox_xsalsa20poly1305.h
    include/sodium/crypto_stream_salsa2012.h
    include/sodium/crypto_hash_sha256.h
    include/sodium/crypto_core_salsa20.h
    include/sodium/crypto_core_salsa2012.h
    include/sodium/crypto_box_curve25519xsalsa20poly1305.h
    include/sodium/crypto_stream.h
    include/sodium/crypto_hash.h
    include/sodium/crypto_aead_aes256gcm.h
    include/sodium/crypto_core_salsa208.h
    include/sodium/crypto_core_hsalsa20.h
    include/sodium/crypto_secretbox.h
    include/sodium/crypto_generichash_blake2b.h
    include/sodium/crypto_verify_32.h
    include/sodium/crypto_shorthash.h
    include/sodium/crypto_auth.h
    include/sodium/export.h
    include/sodium/crypto_core_hchacha20.h
    include/sodium/crypto_onetimeauth_poly1305.h
    include/sodium/crypto_onetimeauth.h
    include/sodium/utils.h
    include/sodium/crypto_scalarmult_curve25519.h
    include/sodium/private/sse2_64_32.h
    include/sodium/private/curve25519_ref10.h
    include/sodium/private/mutex.h
    include/sodium/private/common.h
    include/sodium/randombytes_sysrandom.h
    include/sodium/crypto_pwhash_argon2i.h
    include/sodium/crypto_box.h
    include/sodium/crypto_stream_salsa20.h
    include/sodium/crypto_sign_edwards25519sha512batch.h
    include/sodium/version.h
    include/sodium/crypto_aead_xchacha20poly1305.h
    include/sodium/randombytes_salsa20_random.h
    include/sodium.h
    crypto_stream/aes128ctr/nacl/int128.h
    crypto_stream/aes128ctr/nacl/consts.h
    crypto_stream/aes128ctr/nacl/common.h
    crypto_stream/salsa20/stream_salsa20.h
    crypto_stream/salsa20/ref/salsa20_ref.h
    crypto_stream/salsa20/xmm6/salsa20_xmm6.h
    crypto_stream/salsa20/xmm6int/u8.h
    crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.h
    crypto_stream/salsa20/xmm6int/salsa20_xmm6int-sse2.h
    crypto_stream/salsa20/xmm6int/u4.h
    crypto_stream/salsa20/xmm6int/u0.h
    crypto_stream/salsa20/xmm6int/u1.h
    crypto_stream/chacha20/ref/chacha20_ref.h
    crypto_stream/chacha20/dolbeau/u8.h
    crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.h
    crypto_stream/chacha20/dolbeau/u4.h
    crypto_stream/chacha20/dolbeau/u0.h
    crypto_stream/chacha20/dolbeau/u1.h
    crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.h
    crypto_stream/chacha20/stream_chacha20.h
    crypto_scalarmult/curve25519/donna_c64/curve25519_donna_c64.h
    crypto_scalarmult/curve25519/scalarmult_curve25519.h
    crypto_scalarmult/curve25519/sandy2x/consts_namespace.h
    crypto_scalarmult/curve25519/sandy2x/fe.h
    crypto_scalarmult/curve25519/sandy2x/ladder.h
    crypto_scalarmult/curve25519/sandy2x/fe51_namespace.h
    crypto_scalarmult/curve25519/sandy2x/ladder_base.h
    crypto_scalarmult/curve25519/sandy2x/curve25519_sandy2x.h
    crypto_scalarmult/curve25519/sandy2x/ladder_base_namespace.h
    crypto_scalarmult/curve25519/sandy2x/ladder_namespace.h
    crypto_scalarmult/curve25519/sandy2x/fe51.h
    crypto_scalarmult/curve25519/ref10/x25519_ref10.h
    crypto_shorthash/siphash24/ref/shorthash_siphash_ref.h
    crypto_onetimeauth/poly1305/sse2/poly1305_sse2.h
    crypto_onetimeauth/poly1305/onetimeauth_poly1305.h
    crypto_onetimeauth/poly1305/donna/poly1305_donna64.h
    crypto_onetimeauth/poly1305/donna/poly1305_donna32.h
    crypto_onetimeauth/poly1305/donna/poly1305_donna.h
    crypto_core/curve25519/ref10/base2.h
    crypto_core/curve25519/ref10/base.h
    crypto_generichash/blake2b/ref/blake2b-load-sse41.h
    crypto_generichash/blake2b/ref/blake2b-load-avx2.h
    crypto_generichash/blake2b/ref/blake2.h
    crypto_generichash/blake2b/ref/blake2b-compress-ssse3.h
    crypto_generichash/blake2b/ref/blake2b-compress-avx2.h
    crypto_generichash/blake2b/ref/blake2b-load-sse2.h
    crypto_generichash/blake2b/ref/blake2b-compress-sse41.h
)

SET(libsodium_SOURCE ${libsodium_SOURCE}
    crypto_kdf/blake2b/kdf_blake2b.c
    crypto_kdf/crypto_kdf.c
    crypto_sign/ed25519/sign_ed25519.c
    crypto_sign/ed25519/ref10/keypair.c
    crypto_sign/ed25519/ref10/obsolete.c
    crypto_sign/ed25519/ref10/sign.c
    crypto_sign/ed25519/ref10/open.c
    crypto_sign/crypto_sign.c
    sodium/utils.c
    sodium/runtime.c
    sodium/core.c
    sodium/version.c
    crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.c
    crypto_secretbox/crypto_secretbox.c
    crypto_secretbox/xchacha20poly1305/secretbox_xchacha20poly1305.c
    crypto_secretbox/crypto_secretbox_easy.c
    crypto_box/curve25519xchacha20poly1305/box_curve25519xchacha20poly1305.c
    crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c
    crypto_box/crypto_box_seal.c
    crypto_box/crypto_box_easy.c
    crypto_box/crypto_box.c
    crypto_pwhash/argon2/argon2.c
    crypto_pwhash/argon2/argon2-encoding.c
    crypto_pwhash/argon2/blake2b-long.c
    crypto_pwhash/argon2/argon2-fill-block-ssse3.c
    crypto_pwhash/argon2/argon2-core.c
    crypto_pwhash/argon2/pwhash_argon2i.c
    crypto_pwhash/argon2/argon2-fill-block-ref.c
    crypto_pwhash/crypto_pwhash.c
    crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c
    crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c
    crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c
    crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c
    crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c
    crypto_pwhash/scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c
    crypto_auth/hmacsha256/auth_hmacsha256.c
    crypto_auth/crypto_auth.c
    crypto_auth/hmacsha512256/auth_hmacsha512256.c
    crypto_auth/hmacsha512/auth_hmacsha512.c
    crypto_hash/sha512/hash_sha512.c
    crypto_hash/sha512/cp/hash_sha512_cp.c
    crypto_hash/crypto_hash.c
    crypto_hash/sha256/cp/hash_sha256_cp.c
    crypto_hash/sha256/hash_sha256.c
    crypto_stream/xchacha20/stream_xchacha20.c
    crypto_stream/aes128ctr/stream_aes128ctr.c
    crypto_stream/aes128ctr/nacl/xor_afternm_aes128ctr.c
    crypto_stream/aes128ctr/nacl/stream_aes128ctr_nacl.c
    crypto_stream/aes128ctr/nacl/consts_aes128ctr.c
    crypto_stream/aes128ctr/nacl/int128_aes128ctr.c
    crypto_stream/aes128ctr/nacl/afternm_aes128ctr.c
    crypto_stream/aes128ctr/nacl/beforenm_aes128ctr.c
    crypto_stream/crypto_stream.c
    crypto_stream/xsalsa20/stream_xsalsa20.c
    crypto_stream/salsa20/ref/salsa20_ref.c
    crypto_stream/salsa20/stream_salsa20.c
    crypto_stream/salsa20/xmm6/salsa20_xmm6.c
    crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.c
    crypto_stream/salsa20/xmm6int/salsa20_xmm6int-sse2.c
    crypto_stream/chacha20/stream_chacha20.c
    crypto_stream/chacha20/ref/chacha20_ref.c
    crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.c
    crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.c
    crypto_stream/salsa208/ref/stream_salsa208_ref.c
    crypto_stream/salsa208/stream_salsa208.c
    crypto_stream/salsa2012/ref/stream_salsa2012_ref.c
    crypto_stream/salsa2012/stream_salsa2012.c
    crypto_verify/sodium/verify.c
    crypto_scalarmult/crypto_scalarmult.c
    crypto_scalarmult/curve25519/donna_c64/curve25519_donna_c64.c
    crypto_scalarmult/curve25519/sandy2x/fe_frombytes_sandy2x.c
    crypto_scalarmult/curve25519/sandy2x/curve25519_sandy2x.c
    crypto_scalarmult/curve25519/sandy2x/fe51_invert.c
    crypto_scalarmult/curve25519/scalarmult_curve25519.c
    crypto_scalarmult/curve25519/ref10/x25519_ref10.c
    crypto_shorthash/siphash24/ref/shorthash_siphash24_ref.c
    crypto_shorthash/siphash24/ref/shorthash_siphashx24_ref.c
    crypto_shorthash/siphash24/shorthash_siphashx24.c
    crypto_shorthash/siphash24/shorthash_siphash24.c
    crypto_shorthash/crypto_shorthash.c
    crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c
    crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c
    crypto_aead/aes256gcm/aesni/aead_aes256gcm_aesni.c
    randombytes/randombytes.c
    randombytes/sysrandom/randombytes_sysrandom.c
    randombytes/nativeclient/randombytes_nativeclient.c
    randombytes/salsa20/randombytes_salsa20_random.c
    crypto_onetimeauth/poly1305/sse2/poly1305_sse2.c
    crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
    crypto_onetimeauth/poly1305/donna/poly1305_donna.c
    crypto_onetimeauth/crypto_onetimeauth.c
    crypto_core/hchacha20/core_hchacha20.c
    crypto_core/curve25519/ref10/curve25519_ref10.c
    crypto_core/hsalsa20/core_hsalsa20.c
    crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c
    crypto_core/salsa/ref/core_salsa_ref.c
    crypto_generichash/crypto_generichash.c
    crypto_generichash/blake2b/ref/blake2b-compress-ref.c
    crypto_generichash/blake2b/ref/blake2b-ref.c
    crypto_generichash/blake2b/ref/blake2b-compress-sse41.c
    crypto_generichash/blake2b/ref/blake2b-compress-ssse3.c
    crypto_generichash/blake2b/ref/blake2b-compress-avx2.c
    crypto_generichash/blake2b/ref/generichash_blake2b.c
    crypto_generichash/blake2b/generichash_blake2.c
    crypto_kx/crypto_kx.c
)

#add_library(libsodium STATIC ${libsodium_HEADERS} ${libsodium_SOURCE})
add_library(libsodium ${libsodium_HEADERS} ${libsodium_SOURCE})
#target_link_libraries(libsodium Qt5::Core Qt5::Concurrent Qt5::Widgets Qt5::Network)
#target_link_libraries(libsodium)

