set(KEY_MBEDTLS_DIR "${CMAKE_SOURCE_DIR}/third_party/mbedtls-3.6.7")
if(NOT EXISTS "${KEY_MBEDTLS_DIR}/SOURCE.json")
    message(FATAL_ERROR "Run uv run --locked python tools/vendor_mbedtls.py first")
endif()
set(KEY_MBEDTLS_MODULES
    asn1parse asn1write bignum bignum_core bignum_mod bignum_mod_raw
    chacha20 chachapoly constant_time ecdsa ecp ecp_curves
    hkdf hmac_drbg md memory_buffer_alloc platform platform_util poly1305 sha1 sha256 sha512)
set(KEY_MBEDTLS_SOURCES)
foreach(module IN LISTS KEY_MBEDTLS_MODULES)
    list(APPEND KEY_MBEDTLS_SOURCES "${KEY_MBEDTLS_DIR}/library/${module}.c")
endforeach()
add_library(key_mbedcrypto STATIC ${KEY_MBEDTLS_SOURCES})
target_include_directories(key_mbedcrypto PUBLIC "${KEY_MBEDTLS_DIR}/include" "${CMAKE_SOURCE_DIR}/Core/Inc")
target_compile_definitions(key_mbedcrypto PUBLIC MBEDTLS_CONFIG_FILE="mbedtls_key_config.h")
target_sources(${CMAKE_PROJECT_NAME} PRIVATE Core/Src/key_crypto.c)
target_link_libraries(${CMAKE_PROJECT_NAME} key_mbedcrypto)
# Until the CTAP credential backend calls these, explicitly retain the actual
# primitives so firmware map/resource results include the compiled crypto code.
# This does not execute them or fabricate successful credential operations.
foreach(api init sha256 hkdf seal open p256_public p256_sign job_begin job_poll job_take job_cancel)
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--undefined=key_crypto_${api}")
endforeach()
