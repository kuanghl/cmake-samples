cmake_minimum_required(VERSION 3.5.1)

project(mbedtls-examples)

add_subdirectory(mbedtls-3.6.2)

add_executable(test_rsa_genkey ${CMAKE_CURRENT_SOURCE_DIR}/rsa_genkey.c)

target_link_libraries(test_rsa_genkey
    PUBLIC mbedtls
           mbedcrypto
           mbedx509)

add_executable(test_rsa_sign ${CMAKE_CURRENT_SOURCE_DIR}/rsa_sign.c)

target_link_libraries(test_rsa_sign
    PUBLIC mbedtls
           mbedcrypto
           mbedx509)

add_executable(test_rsa_verify ${CMAKE_CURRENT_SOURCE_DIR}/rsa_verify.c)

target_link_libraries(test_rsa_verify
    PUBLIC mbedtls
           mbedcrypto
           mbedx509)

add_executable(test_pk_decrypt ${CMAKE_CURRENT_SOURCE_DIR}/pk_decrypt.c)

target_link_libraries(test_pk_decrypt
    PUBLIC mbedtls
           mbedcrypto
           mbedx509)

add_executable(test_pk_encrypt ${CMAKE_CURRENT_SOURCE_DIR}/pk_encrypt.c)

target_link_libraries(test_pk_encrypt
    PUBLIC mbedtls
           mbedcrypto
           mbedx509)

add_executable(sign_c ${CMAKE_CURRENT_SOURCE_DIR}/sign_c.c)

target_link_libraries(sign_c
    PUBLIC mbedtls
           mbedcrypto
           mbedx509)

add_executable(encrypt_c ${CMAKE_CURRENT_SOURCE_DIR}/encrypt_c.c)

target_link_libraries(encrypt_c
    PUBLIC mbedtls
           mbedcrypto
           mbedx509)