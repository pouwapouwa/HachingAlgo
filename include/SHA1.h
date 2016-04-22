/* This code is public-domain - it is based on libcrypt
 * placed in the public domain by Wei Dai and other contributors.
 */

#ifndef SHA1_H
#define SHA1_H

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64
#define DIGEST_SIZE 40
#define PROG_NAME "SHA1"

#define AC0  0x5a827999
#define AC20 0x6ed9eba1
#define AC40 0x8f1bbcdc
#define AC60 0xca62c1d6

#define S0 0x67452301
#define S1 0xefcdab89
#define S2 0x98badcfe
#define S3 0x10325476
#define S4 0xc3d2e1f0

/**
 * SHA1 Algorithm Info.
 */
typedef struct sha1_ctx {
    uint32_t buffer[BLOCK_LENGTH/4];
    uint32_t state[HASH_LENGTH/4];
    uint32_t byteCount;
    uint8_t bufferOffset;
    uint8_t keyBuffer[BLOCK_LENGTH];
    uint8_t innerHash[HASH_LENGTH];
} sha1_ctx;

/**
 * Functions Available
 **/

/* Fill sha1nfo struct with data, and hash it when the block is full */
void sha1_addUncounted (sha1_ctx *, uint8_t);
/* sha1 hash algorithm */
void sha1_hashBlock (sha1_ctx *);
/* Init sha1nfo struct for hashing */
void sha1_init (sha1_ctx *);
/* Append the padding to the message, in sha1nfo struct */
void sha1_pad (sha1_ctx *);
/* Last step of hash function  */
uint8_t* sha1_result (sha1_ctx *);
/* Choose data to write */
void sha1_write (sha1_ctx *, uint8_t *, size_t);
/* Increase byteCount */
void sha1_write_byte (sha1_ctx *, uint8_t);
/* Select data to parse, with FILE as input */
void sha1_write_stream (sha1_ctx *, FILE *);


#endif /* SHA_1 */
