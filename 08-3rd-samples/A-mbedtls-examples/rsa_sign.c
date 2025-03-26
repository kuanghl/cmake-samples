/*
 *  RSA/SHA-256 signature creation program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include <stdio.h>
#include <string.h>

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"
/* md.h is included this early since MD_CAN_XXX macros are defined there. */
#include "mbedtls/md.h"

#include "mbedtls/rsa.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

int main(int argc, char *argv[])
{
    mbedtls_rsa_context rsa;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_sign";

    FILE *f;
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    size_t i;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    char filename[512];

    // 1. 初始化随机数熵和加密种子
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
        &entropy, (const unsigned char *)pers,
        strlen(pers));
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
            ret);
        goto exit;
    }

    // 2. 初始化rsa上下文
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

    if (argc != 2) {
        mbedtls_printf("usage: rsa_sign <filename>\n");

#if defined(_WIN32)
        mbedtls_printf("\n");
#endif

        goto exit;
    }

    mbedtls_printf("\n  . Reading private key from rsa_priv.txt");
    fflush(stdout);

    // 3. 读取私钥并导入rsa上下文
    if ((f = fopen("rsa_priv.txt", "rb")) == NULL) {
        mbedtls_printf(" failed\n  ! Could not open rsa_priv.txt\n" \
                       "  ! Please run rsa_genkey first\n\n");
        goto exit;
    }

    if ((ret = mbedtls_mpi_read_file(&N, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&E, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&D, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&P, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&Q, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&DP, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&DQ, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&QP, 16, f)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_read_file returned %d\n\n", ret);
        fclose(f);
        goto exit;
    }
    fclose(f);

    if ((ret = mbedtls_rsa_import(&rsa, &N, &P, &Q, &D, &E)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_import returned %d\n\n",
                       ret);
        goto exit;
    }

    if ((ret = mbedtls_rsa_complete(&rsa)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_complete returned %d\n\n",
                       ret);
        goto exit;
    }

    // 4. 验证私钥合法性
    mbedtls_printf("\n  . Checking the private key");
    fflush(stdout);
    if ((ret = mbedtls_rsa_check_privkey(&rsa)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_check_privkey failed with -0x%0x\n",
                       (unsigned int) -ret);
        goto exit;
    }

    // 5. 对输入文件计算hash值,并对hash值签名
    mbedtls_printf("\n  . Generating the RSA/SHA-256 signature");
    fflush(stdout);
    if ((ret = mbedtls_md_file(
             mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
             argv[1], hash)) != 0) {
        mbedtls_printf(" failed\n  ! Could not open or read %s\n\n", argv[1]);
        goto exit;
    }

    if( ( ret = mbedtls_rsa_pkcs1_sign( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
                                    MBEDTLS_MD_SHA256, 32, hash, buf) ) != 0 )
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n",
                       (unsigned int) -ret);
        goto exit;
    }

    // 6. 将签名后的数据写入一个.sig后缀的文件中及打印签名信息
    mbedtls_snprintf(filename, sizeof(filename), "%s.sig", argv[1]);
    if ((f = fopen(filename, "wb+")) == NULL) {
        mbedtls_printf(" failed\n  ! Could not create %s\n\n", argv[1]);
        goto exit;
    }

    for (i = 0; i < mbedtls_rsa_get_len(&rsa); i++) {
        mbedtls_fprintf(f, "%02X%s", buf[i],
                        (i + 1) % 16 == 0 ? "\r\n" : " ");
    }

    fclose(f);

    mbedtls_printf("\n  . Done (created \"%s\")\n\n", filename);

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa);
    mbedtls_mpi_free(&N); 
    mbedtls_mpi_free(&P); 
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); 
    mbedtls_mpi_free(&E); 
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ); 
    mbedtls_mpi_free(&QP);

    mbedtls_exit(exit_code);
}
