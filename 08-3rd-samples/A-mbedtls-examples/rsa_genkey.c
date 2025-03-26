/*
 *  Example RSA key generation program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include <stdio.h>
#include <string.h>

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"

#define KEY_SIZE 2048
#define EXPONENT 65537

int main(void)
{
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;

    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    FILE *fpub  = NULL;
    FILE *fpriv = NULL;
    const char *pers = "rsa_genkey";

    // 1. 初始化rsa上下文
    mbedtls_rsa_init(&rsa);
    // mbedtls_rsa_set_padding();
    mbedtls_mpi_init(&N); 
    mbedtls_mpi_init(&P); 
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); 
    mbedtls_mpi_init(&E); 
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ); 
    mbedtls_mpi_init(&QP);

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    // 2. 初始化随机数熵及加密种子
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE);
    fflush(stdout);

    // 3. 生成公钥和私钥并导出及写入对应文件
    if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                   EXPONENT)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n  . Exporting the public  key in rsa_pub.txt....");
    fflush(stdout);

    if ((ret = mbedtls_rsa_export(&rsa, &N, &P, &Q, &D, &E)) != 0 ||
        (ret = mbedtls_rsa_export_crt(&rsa, &DP, &DQ, &QP))      != 0) {
        mbedtls_printf(" failed\n  ! could not export RSA parameters\n\n");
        goto exit;
    }

    if ((fpub = fopen("rsa_pub.txt", "wb+")) == NULL) {
        mbedtls_printf(" failed\n  ! could not open rsa_pub.txt for writing\n\n");
        goto exit;
    }

    if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, fpub)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = ", &E, 16, fpub)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n  . Exporting the private key in rsa_priv.txt...");
    fflush(stdout);

    if ((fpriv = fopen("rsa_priv.txt", "wb+")) == NULL) {
        mbedtls_printf(" failed\n  ! could not open rsa_priv.txt for writing\n");
        goto exit;
    }

    if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = ", &E, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("D = ", &D, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("P = ", &P, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("Q = ", &Q, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("DP = ", &DP, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("DQ = ", &DQ, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("QP = ", &QP, 16, fpriv)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
        goto exit;
    }
    mbedtls_printf(" ok\n\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    if (fpub  != NULL) {
        fclose(fpub);
    }

    if (fpriv != NULL) {
        fclose(fpriv);
    }

    mbedtls_mpi_free(&N); 
    mbedtls_mpi_free(&P); 
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); 
    mbedtls_mpi_free(&E); 
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ); 
    mbedtls_mpi_free(&QP);
    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    mbedtls_exit(exit_code);
}
