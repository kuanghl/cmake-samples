/*
 * Copyright 2020-2022. Heekuck Oh, all rights reserved
 * This document was created for current students of the ERICA Software Department at Hanyang University.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <gmp.h>
#include "pkcs.h"
#include "sha2.h"
#include "random.h"

/*
 * rsa_generate_key() - generates RSA keys e, d and n in octet strings.
 * If mode = 0, then e = 65537 is used. Otherwise e will be randomly selected.
 * Carmichael's totient function Lambda(n) is used.
 */
void rsa_generate_key(void *_e, void *_d, void *_n, int mode)
{
    mpz_t p, q, lambda, e, d, n, gcd;
    gmp_randstate_t state;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(p, q, lambda, e, d, n, gcd, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());
    /*
     * Generate prime p and q such that 2^(RSAKEYSIZE-1) <= p*q < 2^RSAKEYSIZE
     */
    do {
        do {
            mpz_urandomb(p, state, RSAKEYSIZE/2);
            mpz_setbit(p, 0);
            mpz_setbit(p, RSAKEYSIZE/2-1);
        } while (mpz_probab_prime_p(p, 50) == 0);
        do {
            mpz_urandomb(q, state, RSAKEYSIZE/2);
            mpz_setbit(q, 0);
            mpz_setbit(q, RSAKEYSIZE/2-1);
        } while (mpz_probab_prime_p(q, 50) == 0);
        mpz_mul(n, p, q);
    } while (!mpz_tstbit(n, RSAKEYSIZE-1));
    /*
     * Generate e and d using Lambda(n)
     */
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_lcm(lambda, p, q);
    if (mode == 0)
        mpz_set_ui(e, 65537);
    else do {
        mpz_urandomb(e, state, RSAKEYSIZE);
        mpz_gcd(gcd, e, lambda);
    } while (mpz_cmp(e, lambda) >= 0 || mpz_cmp_ui(gcd, 1) != 0);
    mpz_invert(d, e, lambda);
    /*
     * Convert mpz_t values into octet strings
     */
    mpz_export(_e, NULL, 1, RSAKEYSIZE/8, 1, 0, e);
    mpz_export(_d, NULL, 1, RSAKEYSIZE/8, 1, 0, d);
    mpz_export(_n, NULL, 1, RSAKEYSIZE/8, 1, 0, n);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(p, q, lambda, e, d, n, gcd, NULL);
}

/*
 * rsa_cipher() - compute m^k mod n
 * If m >= n then returns PKCS_MSG_OUT_OF_RANGE, otherwise returns 0 for success.
 */
static int rsa_cipher(void *_m, const void *_k, const void *_n)
{
    mpz_t m, k, n;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(m, k, n, NULL);
    /*
     * Convert big-endian octets into mpz_t values
     */
    mpz_import(m, RSAKEYSIZE/8, 1, 1, 1, 0, _m);
    mpz_import(k, RSAKEYSIZE/8, 1, 1, 1, 0, _k);
    mpz_import(n, RSAKEYSIZE/8, 1, 1, 1, 0, _n);
    /*
     * Compute m^k mod n
     */
    if (mpz_cmp(m, n) >= 0) {
        mpz_clears(m, k, n, NULL);
        return PKCS_MSG_OUT_OF_RANGE;
    }
    mpz_powm(m, m, k, n);
    /*
     * Convert mpz_t m into the octet string _m
     */
    mpz_export(_m, NULL, 1, RSAKEYSIZE/8, 1, 0, m);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(m, k, n, NULL);
    return 0;
}

typedef struct {
    size_t hashLen;
    size_t messageLimitLen;
    void (*hashFunction)(const unsigned char *message, unsigned int length, unsigned char *digit);
} hashInfo;

/** @brief Hash-related information returned
 *  @param sha2_ndx : SHA2 hash to use
 *  @result : hashInfo(hashLen: hash length, messageLimitLen: exponential product of input message maximum length_2)
 */
static hashInfo getHashInfo(const int sha2_ndx){
    switch(sha2_ndx){
        case SHA224:
            return (hashInfo){SHA224_DIGEST_SIZE, 64, sha224};
            break;
        case SHA256:
            return (hashInfo){SHA256_DIGEST_SIZE, 64, sha256};
            break;
        case SHA384:
            return (hashInfo){SHA384_DIGEST_SIZE, 128, sha384};
            break;
        case SHA512:
            return (hashInfo){SHA512_DIGEST_SIZE, 128, sha512};
            break;
        case SHA512_224:
            return (hashInfo){SHA224_DIGEST_SIZE, 128, sha512_224};
            break;
        case SHA512_256:
            return (hashInfo){SHA256_DIGEST_SIZE, 128, sha512_256};
            break;
        default:
            return (hashInfo){-1, 0, sha224};
            break;
    }
}

static int i2osp(unsigned char *str, uint64_t x, size_t xlen) {
    int tmp;
    if (x >> (8 * xlen) != 0) {
        printf("integer too large\n");
        return 1;
    }

    for (int i = 1; i <= xlen; i++) {
        tmp = 255 & x;
        str[xlen - i] = (uint8_t)tmp;
        x = x >> 8;
    }

    return 0;
}

static int mgf1(unsigned char *mgf, void *mgfseed, size_t seedLen, size_t maskLen, int sha2_ndx) {
    // set hLen
    size_t hlen = 0;
    hashInfo hi = getHashInfo(sha2_ndx);
    hlen = hi.hashLen;
    
    // check "mask too long" error
    if ((maskLen >> 32) > hlen ) {
        return PKCS_HASH_TOO_LONG;
    }

    // set ceil(maskLen / hLen)
    int l = (maskLen - maskLen % hlen) / hlen;
    for (int i = 0; i <= l; i++) {
        unsigned char c[4];
        unsigned char h[seedLen + 4], tmp[hlen];
        // C = I2OSP(i, 4)
        i2osp(c, i, 4);

        // mgfSeed || C
        memcpy(h, mgfseed, seedLen);
        memcpy(h+seedLen, c, 4);
        
        //Hash(mgfSeed || C)
        hi.hashFunction(h, seedLen+4, tmp);

        if (i != l) {
            // T = T || Hash(mgfSeed || C)
            memcpy(mgf+(i*hlen),tmp,hlen);
        }
        else {
            // Cutting more than maskLen
            memcpy(mgf+(i*hlen),tmp,maskLen % hlen);
        }
    }
    return 0;
}

/*
 * rsaes_oaep_encrypt() - RSA encrytion with the EME-OAEP encoding method
 * The result of encrypting message m of length len bytes with public key (e, n) is stored in c.
 * label can be omitted by entering NULL as the label string that identifies the data.
 * sha2_ndx is the index value of the SHA-2 hash function to be used: select from SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256.
 * The size of c should be the same as RSAKEYSIZE.
 * 0 if successful, otherwise an error code will be passed.
 */
int rsaes_oaep_encrypt(const void *m, size_t mLen, const void *label, const void *e, const void *n, void *c, int sha2_ndx) {
    // PKCS_LABEL_TOO_LONG – Label length exceeds limits [RSAES-OAEP]
    if (strlen(label) >= 0x1fffffffffffffffLL)
        return PKCS_LABEL_TOO_LONG;
    
    size_t hLen;
    unsigned char *lHash;
    hashInfo hi = getHashInfo(sha2_ndx);
    
    // Determine hLen based on sha2_ndx and save label Hash to lHash
    hLen = hi.hashLen;
    lHash = malloc(sizeof(unsigned char) * hLen);

    hi.hashFunction(label, strlen(label), lHash);

    // PKCS_MSG_TOO_LONG – Input message is too long and exceeds the limit
    if (mLen > RSAKEYSIZE / 8 - 2 * hLen - 2)
        return PKCS_MSG_TOO_LONG;

    // Produces Padding Stirng based on RSAKEYSIZE, hLen, mLen
    size_t psLen = RSAKEYSIZE / 8 - 2 - 2 * hLen - mLen;

    unsigned char *PaddingString = calloc(psLen, sizeof(unsigned char));


    // Create DataBlock based on hLen, mLen, psLen
    size_t dbLen = hLen + psLen + 1 + mLen;
    unsigned char *DataBlock = malloc(sizeof(unsigned char) * dbLen);

    // Connect lHash, PaddingStirng, 0x01 and Message to the DataBlock in turn
    unsigned char temp[1] = {0x01};
    memcpy(DataBlock, lHash, hLen);
    memcpy(DataBlock + hLen, PaddingString, psLen);
    memcpy(DataBlock + hLen + psLen, temp, 1);
    memcpy(DataBlock + hLen + psLen + 1, m, mLen);

    // Generate random byte string seed
    unsigned char *seed = malloc(sizeof(unsigned char) * hLen);
    arc4random_buf(seed, hLen);

    // Put seed into MGF, raw dbMask
    unsigned char *dbMask = malloc(sizeof(unsigned char) * dbLen);
    mgf1(dbMask, seed, hLen, dbLen, sha2_ndx);

    // Generate MaskedDataBlock with mgf1(dbMask) XOR DataBlock
    unsigned char *MaskedDataBlock = malloc(sizeof(unsigned char) * dbLen);
    for (int i = 0; i < dbLen; i++) {
        MaskedDataBlock[i] = dbMask[i] ^ DataBlock[i];
    }

    // Put a mask data block in the MGF to get a seed mask
    unsigned char *seedMask = malloc(sizeof(unsigned char) * hLen);
    mgf1(seedMask, MaskedDataBlock, dbLen, hLen, sha2_ndx);

    // Generate MaskedSeed with mgf2(seedMask) XOR seed
    unsigned char *MaskedSeed = malloc(sizeof(unsigned char) * hLen);
    for (int i = 0; i < hLen; i++) {
        MaskedSeed[i] = seedMask[i] ^ seed[i];
    };

    // Connect 0x00, MaskedSeed, and MaskedDataBlock in order to EncodedMessage
    unsigned char *EncodedMessage = malloc(sizeof(unsigned char) * RSAKEYSIZE / 8);
    temp[0] = 0x00;
    memcpy(EncodedMessage, temp, 1);
    memcpy(EncodedMessage + 1, MaskedSeed, hLen);
    memcpy(EncodedMessage + 1 + hLen, MaskedDataBlock, dbLen);

    // Encoding EncodedMessage as rsa
    int rsa_result = rsa_cipher(EncodedMessage, e, n);
    if(rsa_result != 0)
        return rsa_result;

    // Store the encrypted EncodedMessage in c
    memcpy(c, EncodedMessage, (RSAKEYSIZE / 8));

    // Free all memory allocated to the used string.
    free(lHash);
    free(PaddingString);
    free(DataBlock);
    free(seed);
    free(dbMask);
    free(seedMask);
    free(MaskedDataBlock);
    free(MaskedSeed);
    free(EncodedMessage);

    return 0;
}
/*
 * rsaes_oaep_decrypt() - RSA decrytion with the EME-OAEP encoding method
 * The ciphertext c uses the private key (d, n) to recover the original message m and length len.
 * The label and sha2_ndx must be the same as those used for encryption.
 * 0 if successful, otherwise an error code will be passed.
 */
/** @brief RSAES_OAEP decryption
 *  @param m : decrypted message
 *  @param mLen : Decrypted message length
 *  @param label : Labels used by RSAES_OAEP
 *  @param d : RSA key private key
 *  @param n : RSA key modulo value n
 *  @param c : Decrypt target cipher statement
 *  @param sha2_ndx : The version of sha2 hash to use
 *  @result : Returns 0 if the decryption succeeds and the defined error code if it fails.
 */
int rsaes_oaep_decrypt(void *m, size_t *mLen, const void *label, const void *d, const void *n, const void *c, int sha2_ndx){
    hashInfo hi = getHashInfo(sha2_ndx);

    if(strlen(label) >= 0x1fffffffffffffffLL)
        return PKCS_LABEL_TOO_LONG; // Exceeding label length limits
    
    // RSA decryption
    unsigned char *encodedMessage = malloc(sizeof(unsigned char) * (RSAKEYSIZE/8));
    memcpy(encodedMessage, c, sizeof(unsigned char) * (RSAKEYSIZE/8));

    int rsa_result = rsa_cipher(encodedMessage, d, n);
    if(rsa_result != 0)
        return rsa_result;

    if(encodedMessage[0] != 0x00)
        return PKCS_INITIAL_NONZERO; // The first byte of the encoded message is not 0.

    // XOR processing-recover original seed, dataBlock
    unsigned char *maskedSeed = malloc(sizeof(unsigned char) * hi.hashLen);
    memcpy(maskedSeed, encodedMessage + 1, sizeof(unsigned char) * hi.hashLen);

    unsigned char *maskedDataBlock = malloc(sizeof(unsigned char) * (RSAKEYSIZE/8 - hi.hashLen - 1));
    memcpy(maskedDataBlock, encodedMessage + hi.hashLen + 1, sizeof(unsigned char) * (RSAKEYSIZE/8 - hi.hashLen - 1));

    unsigned char *seed = malloc(sizeof(unsigned char) * hi.hashLen);
    unsigned char *dataBlock = malloc(sizeof(unsigned char) * (RSAKEYSIZE/8 - hi.hashLen - 1));
    mgf1(seed, maskedDataBlock, RSAKEYSIZE/8 - hi.hashLen - 1, hi.hashLen, sha2_ndx);

    for (int i = 0; i < hi.hashLen; ++i)
        seed[i] ^= maskedSeed[i];

    mgf1(dataBlock, seed, hi.hashLen, RSAKEYSIZE/8 - hi.hashLen - 1, sha2_ndx);

    for (int i = 0; i < RSAKEYSIZE/8 - hi.hashLen - 1; ++i)
        dataBlock[i] ^= maskedDataBlock[i];

    // Restore the original message
    // ... Check Hash(label)
    unsigned char *labelHash = malloc(sizeof(unsigned char) * hi.hashLen);
    memcpy(labelHash, dataBlock, sizeof(unsigned char) * hi.hashLen);

    unsigned char *labelHash_inp = malloc(sizeof(unsigned char) * hi.hashLen);
    hi.hashFunction(label, strlen(label), labelHash_inp);

    if(memcmp(labelHash, labelHash_inp, hi.hashLen) != 0)
        return PKCS_HASH_MISMATCH; // label hash mismatch

    // ... Check padingString
    size_t ptr = hi.hashLen;
    for(;ptr < RSAKEYSIZE/8 - hi.hashLen - 1 && dataBlock[ptr] == 0x00; ++ptr);
    unsigned char divider = ptr < RSAKEYSIZE/8 - hi.hashLen - 1 ? dataBlock[ptr] : 0x00;

    if(divider != 0x01)
        return PKCS_INVALID_PS; // The value after paddingString is not 0x01

    // ...are confirming and decrypting messages
    *mLen = RSAKEYSIZE/8 - hi.hashLen - 1 - ++ptr;
    memcpy(m, dataBlock + ptr, sizeof(char) * *mLen);

    // Release dynamic memory allocation
    free(encodedMessage);
    free(maskedSeed);
    free(maskedDataBlock);
    free(seed);
    free(dataBlock);
    free(labelHash);
    free(labelHash_inp);
    return 0;
}

/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 * The result of signing message m of length len bytes with private key (d, n) is stored in s.
 * The size of s should be equal to RSAKEYSIZE. or 0 if successful, otherwise an error code is passed.
 */
static int emsa_pss_encode(const void *m, size_t mLen, unsigned char *encodedMessage, int sha2_ndx){
    int emLen = RSAKEYSIZE / 8;
    unsigned char *H;
    
    //step 2
    hashInfo hi = getHashInfo(sha2_ndx);
    int hLen = hi.hashLen;
    
    //step3
    if(emLen < hLen * 2 + 2) return PKCS_HASH_TOO_LONG;
    
    unsigned char *mHash = malloc(sizeof(unsigned char) * hi.hashLen);
    hi.hashFunction(m, strlen(m), mHash);
    
    //step1
    if(mLen >= 0x1fffffffffffffffLL) return PKCS_MSG_TOO_LONG;
    
    //salt rand, sLen = hLen
    //step 4
    unsigned char *salt = malloc(sizeof(unsigned char) * hLen);
    arc4random_buf(salt, hLen);
    
    //step 5 mdot
    size_t mdotLen = 8 + hLen * 2;
    unsigned char *mdot = malloc(sizeof(unsigned char) * mdotLen);
    unsigned char temp[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(mdot, temp, 8);
    memcpy(mdot + 8, mHash, hLen);
    memcpy(mdot + 8 + hLen, salt, hLen);

    //step 6 ***
    H = malloc(sizeof(unsigned char) * hLen);
    hi.hashFunction(mdot, mdotLen, H);
    
    //step 7
    size_t dbLen = emLen - hLen - 1;
    size_t psLen = dbLen - hLen - 1;
    unsigned char *ps = calloc(psLen, sizeof(unsigned char)); //fill 0
    
    //DB
    //step 8
    unsigned char *DB = malloc(sizeof(unsigned char) * dbLen);
    unsigned char tmp[1] = {0x01};
    memcpy(DB, ps, psLen);
    memcpy(DB + psLen, tmp, 1);
    memcpy(DB + psLen + 1, salt, hLen);
    
    //step 9
    unsigned char *dbMask = malloc(sizeof(unsigned char) * dbLen);
    mgf1(dbMask, H, hLen, dbLen, sha2_ndx);

    //step 10
    unsigned char *maskedDB = malloc(sizeof(unsigned char) * dbLen);
    for (int i = 0; i < dbLen; i++) {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }
    
    //step 11 & 12
    unsigned char tmp1[1] = {0xbc};
    memcpy(encodedMessage, maskedDB, dbLen);
    memcpy(encodedMessage + dbLen, H, hLen);
    memcpy(encodedMessage + dbLen + hLen, tmp1, 1);

    if ((encodedMessage[0] & 0x80) >> 7 == 1)
       encodedMessage[0] ^= 0x80;
    
    free(mHash);
    free(H);
    free(ps);
    free(dbMask);
    free(maskedDB);
    free(mdot);
    free(salt);

    return 0;
}

/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 * The result of signing message m of length len bytes with private key (d, n) is stored in s.
 * The size of s should be equal to RSAKEYSIZE. or 0 if successful, otherwise an error code is passed.
 */
int rsassa_pss_sign(const void *m, size_t mLen, const void *d, const void *n, void *s, int sha2_ndx){
    unsigned char *encodedMessage = malloc(sizeof(unsigned char) * (RSAKEYSIZE / 8));
    int eps_result = emsa_pss_encode(m, mLen, encodedMessage, sha2_ndx);
    if(eps_result != 0)
        return eps_result; // This error is returned if an error occurs during encode message generation.
    
    rsa_cipher(encodedMessage, d, n);
    
    memcpy(s, encodedMessage, RSAKEYSIZE / 8);

    return 0;
}

/*
 * rsassa_pss_verify - RSA Signature Scheme with Appendix
 * Verify that the signature of a message m of length len bytes is s using the public key (e, n).
 * 0 if successful, otherwise an error code will be passed.
 */
int rsassa_pss_verify(const void *m, size_t mLen, const void *e, const void *n, const void *s, int sha2_ndx){
    size_t hLen, sLen;
    unsigned char *mHash, *Hdot;

    //step 1
    if (mLen >= 0x1fffffffffffffffLL) return PKCS_MSG_TOO_LONG;
    
    unsigned char *encodedMessage = malloc(sizeof(unsigned char) * (RSAKEYSIZE / 8));
    memcpy(encodedMessage, s, RSAKEYSIZE / 8);
    int rsa_ret = rsa_cipher(encodedMessage, e, n);
    if(rsa_ret)
        return rsa_ret;

    //step 2
    hashInfo hi = getHashInfo(sha2_ndx);
    hLen = hi.hashLen;
    mHash = malloc(sizeof(unsigned char) * hLen);
    hi.hashFunction(m, strlen(m), mHash);
    sLen = hLen;
    
    //step 3
    if (RSAKEYSIZE < hLen * 2 + 2) return PKCS_HASH_TOO_LONG;
    
    //step 4
    if (encodedMessage[RSAKEYSIZE / 8 - 1] != 0xbc) return PKCS_INVALID_LAST;
    
    //step 5
    size_t emLen = RSAKEYSIZE / 8;
    size_t dbLen = emLen - hLen - 1;

    unsigned char *maskedDB = malloc(sizeof(unsigned char) * (dbLen));
    for (int i = 0; i < dbLen; i++) {
        maskedDB[i] = encodedMessage[i];
    }
    unsigned char *H = malloc(sizeof(unsigned char) * (hLen));
    for (int i = 0; i < hLen; i++) {
        H[i] = encodedMessage[dbLen + i];
    }
    
    //step 6 *** leftmost (RSAKEYSIZE - embits) * 8bits = 0x00
    if ((encodedMessage[0] & 0x80) >> 7 != 0)
       return PKCS_INVALID_INIT;
    
    //step 7
    unsigned char *dbMask = malloc(sizeof(unsigned char) * dbLen);
    mgf1(dbMask, H, hLen, dbLen, sha2_ndx);
    
    //step 8
    unsigned char *DB = malloc(sizeof(unsigned char) * dbLen);
    for (int i = 0; i < dbLen; i++) {
        DB[i] = maskedDB[i] ^ dbMask[i];
    }
    
    //step 9 *** leftmost (8 * RSAKEYSIZE - embits = 0) = 0
    if ((DB[0] & 0x80) >> 7 == 1)
        DB[0] ^= 0x80;
    
    //step 10 
    for (int i = 0; i < (emLen - hLen - sLen - 2); i++) {
        if (DB[i] != 0x00) return PKCS_INVALID_PD2;
    }
    if(DB[emLen - hLen - sLen - 2] != 0x01) return PKCS_INVALID_PD2;
    
    //step 11
    unsigned char *salt = malloc(sizeof(unsigned char) * sLen);
    for (int i = 0; i < sLen; i++) {
        salt[i] = DB[dbLen - sLen + i];
    }    
    
    //step 12
    unsigned char *mdot = malloc(sizeof(unsigned char) * (hLen + sLen + 8));
    unsigned char tmp[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(mdot, tmp, 8);
    memcpy(mdot + 8, mHash, hLen);
    memcpy(mdot + 8 + hLen, salt, sLen);
    
    //step 13 *** Hdot type error
    Hdot = malloc(sizeof(unsigned char) * hLen);
    hi.hashFunction(mdot, 8 + hLen + sLen, Hdot);
    
    //step 14
    if(memcmp(Hdot, H, hLen))
        return PKCS_HASH_MISMATCH;
    
    return 0;
}