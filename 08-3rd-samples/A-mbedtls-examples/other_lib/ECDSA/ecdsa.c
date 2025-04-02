/*
 * Copyright 2020-2022. Heekuck Oh, all rights reserved
 * This document was created for current students of the ERICA Software Department at Hanyang University.
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <gmp.h>
#include "ecdsa.h"
#include "sha2.h"
#include "random.h"

typedef struct {
	size_t hashLen;
	size_t messageLimitLen;
	void (*hashFunction)(const unsigned char *message, unsigned int length,
											 unsigned char *digit);
} hashInfo;

static hashInfo getHashInfo(const int sha2_ndx) {
	switch (sha2_ndx) {
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

const int a_sign = -1;
const unsigned int a = 3;
mpz_t p, n;
ecdsa_p256_t *G;

/** @brief Addition on ECC point, rpoint = point1 + point2
 *  @note mpz_t p, the integer a must be defined.
 *        p = prime number(modulo)
 *  @param rpoint : addition result of ECC point
 *  @param point1 : Non infinite origin target of ECC point
 *  @param point2 : Non infinite origin target of ECC point
 *  @example ecc_add(&result, &P, &Q);
 *  @return 0 if success, 1 if INF_0
 */
static int ecc_add(ecdsa_p256_t *rpoint, const ecdsa_p256_t *const point1, const ecdsa_p256_t *const  point2){
	// Initialize the point value to the mpz value..
	// lamda, lamda_b, multi2x is extra memory space required for ECC operations. (Temporary variable)
	mpz_t x1, x2, x3, y1, y2, y3, lamda, lamda_b, multi2x;
	mpz_inits(x1, x2, x3, y1, y2, y3, lamda, lamda_b, multi2x, NULL);
	mpz_import(x1, ECDSA_P256/8, 1, sizeof(point1 -> x[0]), 1, 0, point1 -> x); 
	mpz_import(y1, ECDSA_P256/8, 1, sizeof(point1 -> y[0]), 1, 0, point1 -> y); 
	mpz_import(x2, ECDSA_P256/8, 1, sizeof(point2 -> x[0]), 1, 0, point2 -> x); 
	mpz_import(y2, ECDSA_P256/8, 1, sizeof(point2 -> y[0]), 1, 0, point2 -> y); 
	
	mpz_mod(x1, x1, p); mpz_mod(y1, y1, p);
	mpz_mod(x2, x2, p); mpz_mod(y1, y1, p);

	if(mpz_cmp(x1, x2) != 0 || mpz_cmp(y1, y2) != 0){
		// P != Q : ECC Point Addition

		//lamda = (y2-y1) / (x2-x1)
		mpz_sub(lamda, y2, y1); mpz_mod(lamda, lamda, p);
		mpz_sub(lamda_b, x2, x1); mpz_mod(lamda_b, lamda_b, p);
		// Infinite origin
		if(mpz_cmp_ui(lamda_b, 0) == 0){
			mpz_clears(x1, x2, x3, y1, y2, y3, lamda, lamda_b, multi2x, NULL);
			return 1;
		}

		mpz_invert(lamda_b, lamda_b, p);

		mpz_mul(lamda, lamda, lamda_b); mpz_mod(lamda, lamda, p);


		// x3
		mpz_powm_ui(x3, lamda, 2, p);
		mpz_sub(x3, x3, x1); mpz_mod(x3, x3, p);
		mpz_sub(x3, x3, x2); mpz_mod(x3, x3, p);

		//y3
		mpz_sub(y3, x1, x3); mpz_mod(y3, y3, p);
		mpz_mul(y3, lamda, y3); mpz_mod(y3, y3, p);
		mpz_sub(y3, y3, y1); mpz_mod(y3, y3, p);
	} else{
		// P == Q : ECC Point Doubling
		// Infinite origin
		if(mpz_cmp_ui(y1, 0) == 0){
			mpz_clears(x1, x2, x3, y1, y2, y3, lamda, lamda_b, multi2x, NULL);
			return 1;
		}

		//lamda = (3*x_1^2 + a) / 2y_1
		mpz_powm_ui(lamda, x1, 2, p);

		mpz_mul_ui(lamda, lamda, 3); mpz_mod(lamda, lamda, p);

		if(a_sign >= 0) 
			mpz_add_ui(lamda, lamda, a);
		else
			mpz_sub_ui(lamda, lamda, a);

		mpz_mul_ui(lamda_b, y1, 2); mpz_mod(lamda_b, lamda_b, p);
		mpz_invert(lamda_b, lamda_b, p);
		mpz_mul(lamda, lamda, lamda_b); mpz_mod(lamda, lamda, p);

		//x3
		mpz_powm_ui(x3, lamda, 2, p);
		mpz_mul_ui(multi2x, x1, 2); mpz_mod(multi2x, multi2x, p);
		mpz_sub(x3, x3, multi2x); mpz_mod(x3, x3, p);

		//y3
		mpz_sub(y3, x1, x3); mpz_mod(y3, y3, p);
		mpz_mul(y3, lamda, y3); mpz_mod(y3, y3, p);
		mpz_sub(y3, y3, y1); mpz_mod(y3, y3, p);
	}

	mpz_export(rpoint -> x, NULL, 1, ECDSA_P256/8, 1, 0, x3);
	mpz_export(rpoint -> y, NULL, 1, ECDSA_P256/8, 1, 0, y3);
	mpz_clears(x1, x2, x3, y1, y2, y3, lamda, lamda_b, multi2x, NULL);

	return 0;
}

/** @brief Multiplication on ECC point, rpoint = point * time
 *  @note mpz_t p, the integer a must be defined. 
 *        p = prime number(modulo)
 *  @param rpoint : Multiplication result of ECC point
 *  @param point : Non infinite origin target of ECC point
 *  @param time : Addition times
 *  @example ecc_mul(&result, P, T);
 *  @return 0 if success, 1 if INF_0
 */
static int ecc_mul(ecdsa_p256_t *rpoint, ecdsa_p256_t point, const mpz_t time){
	ecdsa_p256_t result;
	int resultINF = 1;
	int pointINF = 0;

	mpz_t t;
	mpz_init(t);
	mpz_set(t, time);

	// Square Multiplication
	while(mpz_cmp_si(t, 0) > 0 && pointINF == 0){
		if(mpz_tstbit(t, 0) == 1){
			if(resultINF == 1){ // Reset infinite loop
				memcpy(&result, &point, sizeof(ecdsa_p256_t));
				resultINF = 0;
			}
			else{
				if(ecc_add(&result, &result, &point) == 1){ // if result + point == O.
					resultINF = 1;
				}
			}
		}
		
		mpz_tdiv_q_2exp(t, t, 1);
		pointINF = ecc_add(&point, &point, &point);
	}
	*rpoint = result;

	mpz_clear(t);

	return resultINF;
}

/*
 * Initialize 256 bit ECDSA parameters
 * Allocate space and initialize the values of system parameters p, n, and G.
 */
void ecdsa_p256_init(void)
{
	unsigned char set_Gx[ECDSA_P256/8] = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
	unsigned char set_Gy[ECDSA_P256/8] = {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};

	mpz_inits(p, n, NULL);
	mpz_set_str(p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
	mpz_set_str(n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
	G = (ecdsa_p256_t *)malloc(sizeof(ecdsa_p256_t));

	for (int i = 0; i < (ECDSA_P256/8); i++) {
		G->x[i] = set_Gx[i];
	}

	for (int i = 0; i < (ECDSA_P256/8); i++) {
		G->y[i] = set_Gy[i];
	}
}

/*
 * Clear 256 bit ECDSA parameters
 * Release the allocated parameter space.
 */
void ecdsa_p256_clear(void)
{
	mpz_clear(p);
	mpz_clear(n);
	free(G);
}

/*
 * ecdsa_p256_key() - generates Q = dG
 * Randomly generate the user's private and public keys.
 */
void ecdsa_p256_key(void *d, ecdsa_p256_t *Q)
{
	gmp_randstate_t rstate;
	mpz_t rand;
	mpz_init(rand);

	// Create random seed and create 256-bit random number rand (=d)
	uint32_t seed = arc4random();
	gmp_randinit_mt(rstate);
	gmp_randseed_ui(rstate, seed);

	mpz_urandomb(rand, rstate, 256);

	// Q = dG
	ecc_mul(Q, *G, rand);
	
	// Export rand to d
	mpz_export(d, NULL, 1, ECDSA_P256/8, 1, 0, rand);

	mpz_clear(rand);
}
/*
 * ecdsa_p256_sign(msg, len, d, r, s) - ECDSA Signature Generation
 * The result of signing message m of length len bytes with private key d is stored in r, s.
 * sha2_ndx is the index value of the SHA-2 hash function to be used: select from SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256. r and s must be 256 bits long.
 * 0 if successful, otherwise an error code will be passed.
 */
int ecdsa_p256_sign(const void *msg, size_t len, const void *d, void *_r, void *_s, int sha2_ndx)
{
	// Define structure according to sha2_ndx
	hashInfo hi = getHashInfo(sha2_ndx);

	// Input message is too long and exceeds the limit
	if (hi.messageLimitLen == 64 && len >= 0x1fffffffffffffffLL)
		return ECDSA_MSG_TOO_LONG;
	
	// Declare the length hLen of e and _e containing the hash value according to the hash function
	size_t hLen;
	unsigned char *_e;

	// 1. e = H(m)
	hLen = hi.hashLen;
	_e = malloc(sizeof(unsigned char) * hLen);
	hi.hashFunction(msg, len, _e);

	// 2. If the length of e is greater than the length of n (256 bits), cut off the latter part
	if (hLen > ECDSA_P256 / 8) {
		// Store the hash value in temp_e only by the length of n
		unsigned char temp_e[ECDSA_P256 / 8];
		for (int i = 0; i < ECDSA_P256 / 8; i++) {
			temp_e[i] = _e[i];
		}
		
		// After initializing _e, regenerate according to the length of n
		free(_e);
		hLen = ECDSA_P256 / 8;
		_e = malloc(sizeof(unsigned char) * hLen);
		
		// Save the saved dun Hash value again to _e
		for (int i = 0; i < ECDSA_P256 / 8; i++) {
			_e[i] = temp_e[i];
		}
	}

	// This is the part that announces the mpz variable to be used.
	mpz_t e, k, r, s, x1, invert_k, mpz_d, temp, temp2;
	gmp_randstate_t state;
	mpz_inits(e, k, r, s, x1, invert_k, mpz_d, temp, temp2, NULL);

	// This is the prep for writing gmp random.
	gmp_randinit_default(state);
	gmp_randseed_ui(state, arc4random());

	// Convert unsigned char _e to mpz_t e
	mpz_import(e, hLen, 1, 1, 1, 0, _e);

	do {
		do {
			// 3. Randomly selected secret value k (0<k<n)
			mpz_set_ui(temp2, 0x01);
			mpz_set(temp, n);
			mpz_sub(temp, n, temp2);
			mpz_urandomm(k, state, temp);
			mpz_add(k, k, temp2);

			// 4. (x1, y1) = kG
			ecdsa_p256_t x1y1;
			ecc_mul(&x1y1, *G, k);
			mpz_import(x1, ECDSA_P256 / 8, 1, 1, 1, 0, x1y1.x);

			// 5. r = x1 mod n
			mpz_mod(r, x1, n);
			
			// If r=0, go to 3. again.
		} while (mpz_cmp_ui(r, 0) == 0);

		// invert_k = k^-1 (mod n)
		mpz_invert(invert_k, k, n);

		// temp = rd mod n;
		mpz_import(mpz_d, ECDSA_P256 / 8, 1, 1, 1, 0, d);
		mpz_mul(temp, r, mpz_d);
		mpz_mod(temp, temp, n);

		// temp = e + rd mod n
		mpz_add(temp, e, temp);
		mpz_mod(temp, temp, n);

		// 6. s = k^-1(e + rd) mod n
		mpz_mul(temp, invert_k, temp);
		mpz_mod(s, temp, n);

		// If s=0, go to 3. again.
	} while (mpz_cmp_ui(s, 0) == 0);

	// 7. (r, s) is the signature value
	mpz_export(_r, NULL, 1, ECDSA_P256 / 8, 1, 0, r);
	mpz_export(_s, NULL, 1, ECDSA_P256 / 8, 1, 0, s);

	// Release all used mpz variables.
	mpz_clears(e, x1, k, r, s, invert_k, mpz_d, temp, temp2, NULL);

	// Returns 0 if all processes are working correctly
	return 0;
}
/*
 * ecdsa_p256_verify(msg, len, Q, r, s) - ECDSA signature veryfication
 * It returns 0 if valid, nonzero otherwise.
 * Verify that the signature of a message m of length len bytes is (r, s) with the public key Q.
 * 0 if successful, otherwise an error code will be passed.
 */
int ecdsa_p256_verify(const void *msg, size_t len, const ecdsa_p256_t *_Q, const void *_r, const void *_s, int sha2_ndx)
{
	// Define structure according to sha2_ndx
	hashInfo hi = getHashInfo(sha2_ndx);

	// Input message is too long and exceeds the limit
	if (hi.messageLimitLen == 64 && len >= 0x1fffffffffffffffLL)
		return ECDSA_MSG_TOO_LONG;
	
	mpz_t tmp, e, r, s;
	mpz_inits(tmp, e, r, s, NULL);
	
	mpz_import(r, ECDSA_P256 / 8, 1, 1, 1, 0, _r);
	mpz_import(s, ECDSA_P256 / 8, 1, 1, 1, 0, _s);

	//step 1
	mpz_set(tmp, n); mpz_sub_ui(tmp, tmp, 1);
	if (mpz_cmp_ui(r, 1) < 0 || mpz_cmp(r, tmp) > 0 || mpz_cmp_ui(s, 1) < 0 || mpz_cmp(s, tmp) > 0){
		mpz_clears(tmp, e, r, s, NULL);
		return ECDSA_SIG_INVALID;
	}
	mpz_clear(tmp);
	
	//step 2
	unsigned char *_e;
	size_t hLen;
	hLen = hi.hashLen;
	_e = malloc(sizeof(unsigned char) * hLen);
	hi.hashFunction(msg, len, _e);
	
	//step 3
	if (hLen > ECDSA_P256/8) {
	unsigned char temp_e[ECDSA_P256/8];
	for (int i = 0; i < ECDSA_P256 / 8; i++) {
		temp_e[i] = _e[i];
		}
	free(_e);
	hLen = ECDSA_P256/8;
	_e = malloc(sizeof(unsigned char) * hLen);
	for (int i = 0; i < ECDSA_P256/8; i++) {
		_e[i] = temp_e[i];
		}
	}

	//step 4. 𝑢1 = 𝑒*s_invert mod 𝑛, 𝑢2 = 𝑟 *𝑠_invert mod 𝑛
	mpz_t u1, u2, s_invert;
	mpz_inits(u1, u2, s_invert, NULL);
	
	mpz_import(e, hLen, 1, 1, 1, 0, _e);

	mpz_invert(s_invert, s, n); //s^-1
	
	
	mpz_mul(u1, e, s_invert); //u1 = e * s_invert
	mpz_mod(u1, u1, n); //u1 = u1 mod n

	mpz_mul(u2, r, s_invert); //u2 = r * s_invert
	mpz_mod(u2, u2, n); //u2 = u2 mod n

	//step 5 (𝑥1, 𝑦1) = 𝑢1𝐺 + 𝑢2𝑄. If (𝑥 1, 𝑦 1)=𝑂, then the signature is invalid.
	mpz_t x1, y1;
	mpz_inits(x1, y1, NULL);
	
	ecdsa_p256_t u1G;
	ecc_mul(&u1G, *G, u1); //u1G

	ecdsa_p256_t u2Q;
	ecc_mul(&u2Q, *_Q, u2); //u2Q
	
	ecdsa_p256_t x1y1;
	int isInfPoint = ecc_add(&x1y1, &u1G, &u2Q); //xi, yi
	

	mpz_import(x1, ECDSA_P256 / 8, 1, 1, 1, 0, x1y1.x);
	mpz_import(y1, ECDSA_P256 / 8, 1, 1, 1, 0, x1y1.y);
	
	//if ( (x1, y1) == O) return ECDSA_SIG_MISMATCH;
	if(isInfPoint == 1){
		mpz_clears(e, s, u1, u2, s_invert, y1, r, x1, NULL);
		return ECDSA_SIG_INVALID;
	}
	mpz_clears(e, s, u1, u2, s_invert, y1, NULL);

	//step 6
	mpz_t r_tmp; //r_tmp = r mod n
	mpz_init(r_tmp);
	mpz_mod(r_tmp, r, n);
	
	mpz_t x1tmp; //x1tmp = x1 mod n
	mpz_init(x1tmp);
	mpz_mod(x1tmp, x1, n);
	
	if(mpz_cmp(r_tmp, x1tmp) != 0){
		mpz_clears(r, r_tmp, x1, x1tmp, NULL);
		return ECDSA_SIG_MISMATCH;
	}
	
	mpz_clears(r, r_tmp, x1, x1tmp, NULL);

	return 0;
}
