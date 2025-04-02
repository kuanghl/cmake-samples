/*
 * Copyright 2020-2022. Heekuck Oh, all rights reserved
 * This document was created for current students of the ERICA Software Department at Hanyang University.
 */
#ifndef _ECDSA_H_
#define _ECDSA_H_

/*
 * It is not possible to change the value arbitrarily to the bit size of the group decimals and times of the elliptic curve P-256.
 */
#define ECDSA_P256 256

/*
 * SHA-2 The index value used to distinguish the series hash function.
 * SHA512_224 and SHA512_256 represent SHA512/224 and SHA512/256, respectively.
 */
#define SHA224      0
#define SHA256      1
#define SHA384      2
#define SHA512      3
#define SHA512_224  4
#define SHA512_256  5

/*
 * This is a list of error codes. If there are no errors, 0 is used.
 */
#define ECDSA_MSG_TOO_LONG  1
#define ECDSA_SIG_INVALID   2
#define ECDSA_SIG_MISMATCH  3

/*
 * A structure representing points on an elliptic curve P-256.
 */
typedef struct {
    unsigned char x[ECDSA_P256/8];
    unsigned char y[ECDSA_P256/8];
} ecdsa_p256_t;

void ecdsa_p256_init(void);
void ecdsa_p256_clear(void);
void ecdsa_p256_key(void *d, ecdsa_p256_t *Q);
int ecdsa_p256_sign(const void *msg, size_t len, const void *d, void *r, void *s, int sha2_ndx);
int ecdsa_p256_verify(const void *msg, size_t len, const ecdsa_p256_t *Q, const void *r, const void *s, int sha2_ndx);

#endif
