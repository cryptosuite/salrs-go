#ifndef KYBER_ALL_H
#define KYBER_ALL_H

#include <stdint.h>
#include <stdio.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE  72
#define _GNU_SOURCE

#ifndef KYBER_K
#define KYBER_K 3 /* Change this for different security strengths */
#endif

/* Don't change parameters below this line */

#define KYBER_N 256
#define KYBER_Q 7681

#if   (KYBER_K == 2) /* Kyber512 */
#define KYBER_ETA 5
#elif (KYBER_K == 3) /* Kyber768 */
#define KYBER_ETA 4
#elif (KYBER_K == 4) /*KYBER1024 */
#define KYBER_ETA 3
#else
#error "KYBER_K must be in {2,3,4}"
#endif

#define KYBER_SYMBYTES 32   /* size in bytes of shared key, hashes, and seeds */

#define KYBER_POLYBYTES              416
#define KYBER_POLYCOMPRESSEDBYTES    96
#define KYBER_POLYVECBYTES           (KYBER_K * KYBER_POLYBYTES)
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)

#define KYBER_INDCPA_MSGBYTES       KYBER_SYMBYTES
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES +  KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES) /* 32 bytes of additional space to save H(pk) */
#define KYBER_CIPHERTEXTBYTES  KYBER_INDCPA_BYTES

#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SYMBYTES

#if   (KYBER_K == 2)
#define CRYPTO_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#define CRYPTO_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#define CRYPTO_ALGNAME "Kyber1024"
#else
#error "KYBER_K must be in {2,3,4}"
#endif
#define gen_a(A,B)  gen_matrix_kyber(A,B,0)
#define gen_at(A,B) gen_matrix_kyber(A,B,1)
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/*
* Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
* coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
*/
typedef struct {
	uint16_t coeffs[KYBER_N];
} poly_kyber;

typedef struct {
	poly_kyber vec[KYBER_K];
} polyvec_kyber;


void gen_matrix_kyber(polyvec_kyber *a, const unsigned char *seed, int transposed);
void pack_sk_kyber(unsigned char *r, const polyvec_kyber *sk);
void unpack_sk_kyber(polyvec_kyber *sk, const unsigned char *packedsk);
void pack_pk_kyber(unsigned char *r, const polyvec_kyber *pk, const unsigned char *seed);
void unpack_pk_kyber(polyvec_kyber *pk, unsigned char *seed, const unsigned char *packedpk);
void shake128_absorb_kyber(uint64_t *s, const unsigned char *input, unsigned int inputByteLen);
void shake128_squeezeblocks_kyber(unsigned char *output, unsigned long long nblocks, uint64_t *s);

void shake256_kyber(unsigned char *output, unsigned long long outlen, const unsigned char *input,  unsigned long long inlen);
void sha3_256_kyber(unsigned char *output, const unsigned char *input,  unsigned long long inlen);
void sha3_512_kyber(unsigned char *output, const unsigned char *input,  unsigned long long inlen);

int verify_kyber(const unsigned char *a, const unsigned char *b, size_t len);

void cmov_kyber(unsigned char *r, const unsigned char *x, size_t len, unsigned char b);
void randombytes_kyber(unsigned char *x, size_t xlen);
uint16_t freeze_kyber(uint16_t x);

uint16_t montgomery_reduce_kyber(uint32_t a);

uint16_t barrett_reduce_kyber(uint16_t a);
void ntt_kyber(uint16_t* poly_kyber);
void invntt_kyber(uint16_t* poly_kyber);

void cbd_kyber(poly_kyber *r, const unsigned char *buf);
void polyvec_compress_kyber(unsigned char *r, const polyvec_kyber *a);
void polyvec_decompress_kyber(polyvec_kyber *r, const unsigned char *a);

void polyvec_tobytes_kyber(unsigned char *r, const polyvec_kyber *a);
void polyvec_frombytes_kyber(polyvec_kyber *r, const unsigned char *a);

void polyvec_ntt_kyber(polyvec_kyber *r);
void polyvec_invntt_kyber(polyvec_kyber *r);

void polyvec_pointwise_acc_kyber(poly_kyber *r, const polyvec_kyber *a, const polyvec_kyber *b);

void polyvec_add_kyber(polyvec_kyber *r, const polyvec_kyber *a, const polyvec_kyber *b);
void poly_compress_kyber(unsigned char *r, const poly_kyber *a);
void poly_decompress_kyber(poly_kyber *r, const unsigned char *a);

void poly_tobytes_kyber(unsigned char *r, const poly_kyber *a);
void poly_frombytes_kyber(poly_kyber *r, const unsigned char *a);

void poly_frommsg_kyber(poly_kyber *r, const unsigned char msg[KYBER_SYMBYTES]);
void poly_tomsg_kyber(unsigned char msg[KYBER_SYMBYTES], const poly_kyber *r);

void poly_getnoise_kyber(poly_kyber *r, const unsigned char *seed, unsigned char nonce);

void poly_ntt_kyber(poly_kyber *r);
void poly_invntt_kyber(poly_kyber *r);

void poly_add_kyber(poly_kyber *r, const poly_kyber *a, const poly_kyber *b);
void poly_sub_kyber(poly_kyber *r, const poly_kyber *a, const poly_kyber *b);
void indcpa_publicseed_kyber(unsigned char *buf);

void indcpa_keypair_kyber(unsigned char *pk,
	unsigned char *sk);

void indcpa_enc_kyber(unsigned char *c,
	const unsigned char *m,
	const unsigned char *pk,
	const unsigned char *coins);

void indcpa_dec_kyber(unsigned char *m,
	const unsigned char *c,
	const unsigned char *sk);

int crypto_kem_keypair_kyber(unsigned char *pk,
	unsigned char *sk);

int crypto_kem_enc_kyber(unsigned char *ct,
	unsigned char *ss,
	const unsigned char *pk);

int crypto_kem_dec_kyber(unsigned char *ss,
	const unsigned char *ct,
	const unsigned char *sk);


#endif // !KYBER_ALL.H

#pragma once
