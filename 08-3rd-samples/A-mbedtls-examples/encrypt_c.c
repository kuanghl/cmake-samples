#include <string.h>
#include <stdlib.h>

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"

#include "mbedtls/ctr_drbg.h"
#include <mbedtls/pem.h>

/**
 * @brief rsa_pkcs1v15_sha256_genkey
 * 
 * @param [out] private_key_pem
 * @param [in] private_key_len
 * @param [out] public_key_pem
 * @param [in] public_key_len
 * @return int 
 *  -- 0  generate key pass
 *  -- -1 generate key faild
 */
int rsa_pkcs1v15_sha256_genkey(char *private_key_pem, int private_key_len, 
                               char *public_key_pem, int public_key_len)
{
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;
    
    int ret = 0;
    unsigned int key_size = 1024;
    int exponent = 65537; // 0x10001
    const char *pers = "rsa_key_generation";

     // 初始化rsa上下文
     mbedtls_rsa_init(&rsa);

    // 初始化随机数生成器
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, 
                          mbedtls_entropy_func, 
                          &entropy,
                          (const unsigned char *)pers, 
                          strlen(pers));

    // 生成秘钥对
    ret = mbedtls_rsa_gen_key(&rsa, 
                              mbedtls_ctr_drbg_random, 
                              &ctr_drbg, 
                              key_size,
                              exponent);
    if (ret != 0) {
        goto exit;
    }

    // 初始化pk上下文
    mbedtls_pk_init(&pk);

    ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) {
        goto exit;
    }

    // 拷贝rsa上下文关联pk上下文
    ret = mbedtls_rsa_copy(mbedtls_pk_rsa(pk), &rsa);
    if (ret != 0) {
        goto exit;
    }

    // 私钥
    ret = mbedtls_pk_write_key_pem(&pk, private_key_pem, private_key_len);
    if (ret != 0) {
        goto exit;
    }

    // 公钥
    ret = mbedtls_pk_write_pubkey_pem(&pk, public_key_pem, public_key_len);
    if (ret != 0) {
        goto exit;
    }

exit:
    mbedtls_pk_free(&pk);
    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

/**
 * @brief rsa_pkcs1v15_sha256_encrypt
 * 
 * @param [in] msg
 * @param [in] msg_len
 * @param [in] public_key_pem
 * @param [out] en_out
 * @param [in] en_len
 * @param [out] olen
 * @return int 
 *  -- 0  encrypt pass
 *  -- -1 encrypt faild
 */
int rsa_pkcs1v15_sha256_encrypt(const unsigned char *msg, size_t msg_len,
                               const char *public_key_pem, char *en_out, int en_len, 
                               size_t *olen)
{
    mbedtls_pk_context pk = {0};
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "mbedtls_pk_encrypt";

    int ret = 0;
    
    if (en_out == NULL) {
        ret = -1;
        goto exit;
    }

    // 初始化随机数生成器
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                          &entropy, (const unsigned char *) pers,
                          strlen(pers));
    // 初始化上下文
    mbedtls_pk_init(&pk);

    // 导入公钥
    ret = mbedtls_pk_parse_public_key(&pk, 
                                      (const unsigned char *)public_key_pem, 
                                      strlen(public_key_pem)+1);
    if (ret != 0) {
        goto exit;
    }

    // 加密
    ret = mbedtls_pk_encrypt(&pk, msg, msg_len,
                             en_out, olen, en_len,
                             mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        goto exit;
    }

    if (en_len < *olen) {
        ret = -1;
        goto exit;
    }

exit:

    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return ret;
}

/**
 * @brief rsa_pkcs1v15_sha256_decrypt
 * 
 * @param [out] msg
 * @param [in] msg_len
 * @param [in] priavte_key_pem
 * @param [in] en_in
 * @param [in] en_len
 * @return int 
 *  -- 0  sign pass
 *  -- -1 sign faild
 */
int rsa_pkcs1v15_sha256_decrypt(char *msg, size_t msg_len,
                             const char *priavte_key_pem, char *en_in, int en_len)
{
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    int ret = 0;
    size_t olen = 0;
    const char *pers = "mbedtls_pk_decrypt";      // Personalization data,
    // that is device-specific identifiers. Can be NULL.
    
    // 初始化随机数生成器
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg,
                          mbedtls_entropy_func,
                          &entropy,
                          (const unsigned char *)pers,
                          strlen(pers));

    //初始化上下文
    mbedtls_pk_init(&pk);

    //导入私钥
    ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)priavte_key_pem,
                               strlen(priavte_key_pem)+1, NULL, 0,
                               mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ret = -1;
        goto exit;
    }



    // 解密
    ret = mbedtls_pk_decrypt(&pk, en_in, en_len, msg, &olen, msg_len,
                             mbedtls_ctr_drbg_random, &ctr_drbg);

exit:

    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return ret;
}

static void test_rsa_pkcs1_gen(void)
{
    int ret = 0;
    char private_key[2048] = {0};
    char public_key[2048] = {0};

    ret = rsa_pkcs1v15_sha256_genkey(private_key, sizeof(private_key), 
                                     public_key, sizeof(public_key));

    printf("rsa_pkcs1v15_sha256_genkey ret=%d\r\n", ret);

    if (ret == 0) {
        printf("%s\r\n", private_key);
        printf("%s\r\n\n", public_key);
    }
}

// 公共变量用于存放加密后的数据
char en_buf[1024] = {0};
size_t olen = 0;

static void test_rsa_pkcs1_encrypt(void)
{

    int ret = 0;

    // 公钥
    char *pub_key = "-----BEGIN PUBLIC KEY-----\n"
                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTt8tp4xNp29CMxy6QS0NzpR6t\n"
                    "8bAcv7ei3NkVM/Nzg3K5wWZRaBTMovbzKCXdXYdC6GutVkG+CEetO3XHM4LhDqW0\n"
                    "vwISTO65/XrvR3zqXD5ZjrJFmtCAvkCwtMAPjqXZ/RJnd8yrXuoz5cRqVgKmq5TZ\n"
                    "lGIIiTPIklxGIGof8QIDAQAB\n"
                    "-----END PUBLIC KEY-----";
    // 原始消息
    char *msg = "A message for signing";

    ret = rsa_pkcs1v15_sha256_encrypt((const unsigned char *)msg, strlen(msg), pub_key, 
                                      en_buf, sizeof(en_buf), &olen);

    printf("rsa_pkcs1v15_sha256_encrypt ret=%d\r\n", ret);
}

static void test_rsa_pkcs1_decrypt(void)
{
    int ret = 0;

    char *private_key = "-----BEGIN RSA PRIVATE KEY-----\n"
                        "MIICXQIBAAKBgQDTt8tp4xNp29CMxy6QS0NzpR6t8bAcv7ei3NkVM/Nzg3K5wWZR\n"
                        "aBTMovbzKCXdXYdC6GutVkG+CEetO3XHM4LhDqW0vwISTO65/XrvR3zqXD5ZjrJF\n"
                        "mtCAvkCwtMAPjqXZ/RJnd8yrXuoz5cRqVgKmq5TZlGIIiTPIklxGIGof8QIDAQAB\n"
                        "AoGAFf1BJoiD5+sBdFmsq6ZxhUWZU+ImEzpTUZpD/riEWNNGe2YLoTlg7acgZH1f\n"
                        "P2hbJ9cZdemfTuQvw52JHE0sktCUM6R0wq5rlbDj740+5yZYzs9FlUntm6UtoU9w\n"
                        "tpd62/iPxovFkguunJB2KBbtP8q0dYQntATEce1TZuS3trUCQQDl7VRYygSb3/HY\n"
                        "ij2ya1592WpgNWgmPvbpmUjGGBvjmnO8Ye1lEy6x69RmGjRrLvFfhWYwcF2HpmYQ\n"
                        "9wXKEwT1AkEA67nc/CdeT4j9jRE/QFXlhVrW8Gq8IfjXFGbGK5BqlTRbty3OpW+L\n"
                        "M9GPqiMC2XxN60peEiANlQ8aUnvbHZexjQJAcz4RGK+ov7fvL+maIuNN6SYf+zjJ\n"
                        "iuHkQBFkOGW9FMdFWxZ6Nj73GJZrTwGzZEWTFZ13KrAnMOZmIfquHCqMQQJBAL+u\n"
                        "x9ATg1FRqDyKBdEfCCDEmXuuj4VggCUK3aKXMNRbWyk9iohkh+F/Sz+icLLBreri\n"
                        "8lPy1JidS14/cRJDRBECQQCT4oNvmV5CYzqkqbgwtLPi/FIjc6Zi26DGxBzL01V+\n"
                        "yTO1ZlOOUOtY4dPBnU4COkdq6hWqum/Q6kiVj91qAUHN\n"
                        "-----END RSA PRIVATE KEY-----";

    char msg[256] = {0};

    ret = rsa_pkcs1v15_sha256_decrypt((char *)msg, sizeof(msg), private_key, en_buf, olen);

    printf("rsa_pkcs1v15_sha256_decrypt ret=%d\r\n", ret);

    printf("msg:%s\r\n\n", msg);
}

int main(int argc, char *argv[])
{
    test_rsa_pkcs1_gen();
    test_rsa_pkcs1_encrypt();
    test_rsa_pkcs1_decrypt();

    return 0;
}
