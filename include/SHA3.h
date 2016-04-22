/*
 *
 */

#ifndef RHASH_SHA3_H
#define RHASH_SHA3_H

#define PROG_NAME "SHA3"
#define sha3_224_hash_size  28
#define sha3_max_permutation_size 25
#define sha3_max_rate_in_qwords 24
#define NumberOfRounds 24


/**
 * MACRO
 **/

#define ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))
#define le2me_64(x) (x)
#define IS_ALIGNED_64(p) (0 == (7 & ((const char*)(p) - (const char*)0)))
#define me64_to_le_str(to, from, length) memcpy((to), (from), (length))


/**
 * SHA3 Algorithm context.
 **/
typedef struct sha3_ctx
{
	/* 1600 bits algorithm hashing state */
	uint64_t hash[sha3_max_permutation_size];
	/* 1536-bit buffer for leftovers */
	uint64_t message[sha3_max_rate_in_qwords];
	/* count of bytes in the message[] buffer */
	unsigned rest;
	/* size of a message block processed at once */
	unsigned block_size;
} sha3_ctx;


/**
 * Functions Available
 **/

/* Initilize context structure for sha3-224 */
void sha3_224_init (sha3_ctx *);
/* Calculate Message Hash  */
void sha3_update (sha3_ctx *, const unsigned char*, size_t);
/* End of the Hashing, storing the hash */
void sha3_final (sha3_ctx *, unsigned char*);

#endif /* RHASH_SHA3_H */
