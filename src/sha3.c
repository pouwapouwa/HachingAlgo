/* sha3.c - an implementation of Secure Hash Algorithm 3 (Keccak).
 * based on the
 * The Keccak SHA-3 submission. Submission to NIST (Round 3), 2011
 * by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche
 *
 * Copyright: 2013 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted,  free of charge,  to any person  obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction,  including without limitation
 * the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
 * and/or sell copies  of  the Software,  and to permit  persons  to whom the
 * Software is furnished to do so.
 *
 * This program  is  distributed  in  the  hope  that it will be useful,  but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  Use this program  at  your own risk!
 */

#include "display.h"
#include "SHA3.h"


/**
 ** Variables
 **/


static FILE *new_output;
static FILE *new_input;


/* SHA3 (Keccak) constants for 24 rounds */
static uint64_t keccak_round_constants[NumberOfRounds] = {
  0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000,
  0x000000000000808B, 0x0000000080000001, 0x8000000080008081,
    0x8000000000008009,
  0x000000000000008A, 0x0000000000000088, 0x0000000080008009,
    0x000000008000000A,
  0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800A,
    0x800000008000000A,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001,
    0x8000000080008008
};


/**
 ** code
 **/


/* Initializing a sha3 context for given number of output bits */
static void
keccak_init (sha3_ctx * ctx, unsigned bits)
{
/* NB: The Keccak capacity parameter = bits * 2 */
/* capacity c = 248 */
/* rate r = b - c */
  unsigned rate = 1600 - bits * 2;

  memset (ctx, 0, sizeof (sha3_ctx));
  ctx->block_size = rate / 8;
}


void
sha3_224_init (sha3_ctx * ctx)
{
  /* output length: l=224 */
  keccak_init (ctx, 224);
}

/* Keccak theta() transformation */
static void
keccak_theta (uint64_t * A)
{
  unsigned int x;
  uint64_t C[5], D[5];

  for (x = 0; x < 5; x++)
    {
      C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    }
  D[0] = ROTL64 (C[1], 1) ^ C[4];
  D[1] = ROTL64 (C[2], 1) ^ C[0];
  D[2] = ROTL64 (C[3], 1) ^ C[1];
  D[3] = ROTL64 (C[4], 1) ^ C[2];
  D[4] = ROTL64 (C[0], 1) ^ C[3];

  for (x = 0; x < 5; x++)
    {
      A[x] ^= D[x];
      A[x + 5] ^= D[x];
      A[x + 10] ^= D[x];
      A[x + 15] ^= D[x];
      A[x + 20] ^= D[x];
    }
}

/* Keccak pi() transformation */
static void
keccak_pi (uint64_t * A)
{
  uint64_t A1;
  A1 = A[1];
  A[1] = A[6];
  A[6] = A[9];
  A[9] = A[22];
  A[22] = A[14];
  A[14] = A[20];
  A[20] = A[2];
  A[2] = A[12];
  A[12] = A[13];
  A[13] = A[19];
  A[19] = A[23];
  A[23] = A[15];
  A[15] = A[4];
  A[4] = A[24];
  A[24] = A[21];
  A[21] = A[8];
  A[8] = A[16];
  A[16] = A[5];
  A[5] = A[3];
  A[3] = A[18];
  A[18] = A[17];
  A[17] = A[11];
  A[11] = A[7];
  A[7] = A[10];
  A[10] = A1;
/* note: A[ 0] is left as is */
}

/* Keccak chi() transformation */
static void
keccak_chi (uint64_t * A)
{
  int i;
  for (i = 0; i < 25; i += 5)
    {
      uint64_t A0 = A[0 + i], A1 = A[1 + i];
      A[0 + i] ^= ~A1 & A[2 + i];
      A[1 + i] ^= ~A[2 + i] & A[3 + i];
      A[2 + i] ^= ~A[3 + i] & A[4 + i];
      A[3 + i] ^= ~A[4 + i] & A0;
      A[4 + i] ^= ~A0 & A1;
    }
}

static void
sha3_permutation (uint64_t * state)
{
  int round;
  for (round = 0; round < NumberOfRounds; round++)
    {
      keccak_theta (state);

/* apply Keccak rho() transformation */
      state[1] = ROTL64 (state[1], 1);
      state[2] = ROTL64 (state[2], 62);
      state[3] = ROTL64 (state[3], 28);
      state[4] = ROTL64 (state[4], 27);
      state[5] = ROTL64 (state[5], 36);
      state[6] = ROTL64 (state[6], 44);
      state[7] = ROTL64 (state[7], 6);
      state[8] = ROTL64 (state[8], 55);
      state[9] = ROTL64 (state[9], 20);
      state[10] = ROTL64 (state[10], 3);
      state[11] = ROTL64 (state[11], 10);
      state[12] = ROTL64 (state[12], 43);
      state[13] = ROTL64 (state[13], 25);
      state[14] = ROTL64 (state[14], 39);
      state[15] = ROTL64 (state[15], 41);
      state[16] = ROTL64 (state[16], 45);
      state[17] = ROTL64 (state[17], 15);
      state[18] = ROTL64 (state[18], 21);
      state[19] = ROTL64 (state[19], 8);
      state[20] = ROTL64 (state[20], 18);
      state[21] = ROTL64 (state[21], 2);
      state[22] = ROTL64 (state[22], 61);
      state[23] = ROTL64 (state[23], 56);
      state[24] = ROTL64 (state[24], 14);

      keccak_pi (state);
      keccak_chi (state);

/* apply iota(state, round) */
      *state ^= keccak_round_constants[round];
    }
}


static void
sha3_process_block (uint64_t hash[25], const uint64_t * block)
{
/* expanded loop */
  hash[0] ^= le2me_64 (block[0]);
  hash[1] ^= le2me_64 (block[1]);
  hash[2] ^= le2me_64 (block[2]);
  hash[3] ^= le2me_64 (block[3]);
  hash[4] ^= le2me_64 (block[4]);
  hash[5] ^= le2me_64 (block[5]);
  hash[6] ^= le2me_64 (block[6]);
  hash[7] ^= le2me_64 (block[7]);
  hash[8] ^= le2me_64 (block[8]);
  hash[9] ^= le2me_64 (block[9]);
  hash[10] ^= le2me_64 (block[10]);
  hash[11] ^= le2me_64 (block[11]);
  hash[12] ^= le2me_64 (block[12]);
  hash[13] ^= le2me_64 (block[13]);
  hash[14] ^= le2me_64 (block[14]);
  hash[15] ^= le2me_64 (block[15]);
  hash[16] ^= le2me_64 (block[16]);
  hash[17] ^= le2me_64 (block[17]);
/* make a permutation of the hash */
  sha3_permutation (hash);
}

#define SHA3_FINALIZED 0x80000000

void
sha3_write_stream (sha3_ctx * ctx, FILE * f)
{
  bool end = false;
  do
  {
    uint8_t tmp[64];
    int i;
    for (i = 0; i < 64; i++)
      tmp[i] = 0;
   
    // Read data, size is the number of elements successfully read
    size_t size = fread (tmp, sizeof (uint8_t), 64, f);
    
    // If the file size is a multiple of BLOCK_LENGTH
    if (size == 0)
      return ;

    uint8_t *tmp2 = malloc (sizeof (uint8_t) * (size));
    // If the block is incomplete
    if (size != 64)
    {
      memcpy (tmp2, tmp, size);
      end = true;
    }
    // If the block is complete
    else
      memcpy (tmp2, tmp, size);
    // Write data in the strcut sha1nfo, and hash it if possible
    sha3_update (ctx, tmp2, size);
    free (tmp2);
  }
  while (!end);
}

void
sha3_update (sha3_ctx * ctx, const unsigned char *msg, size_t size)
{
  size_t index = (size_t) ctx->rest;
  size_t block_size = (size_t) ctx->block_size;

  if (ctx->rest & SHA3_FINALIZED)
    return;			/* too late for additional input */
  ctx->rest = (unsigned) ((ctx->rest + size) % block_size);
  
/* fill partial block */
  if (index)
    {
      size_t left = block_size - index;
      memcpy ((char *) ctx->message + index, msg,
	      (size < left ? size : left));
      if (size < left)
	return;

      /* process partial block */
      sha3_process_block (ctx->hash, ctx->message);
      msg += left;
      size -= left;
    }
  while (size >= block_size)
    {
      uint64_t *aligned_message_block;
      if (IS_ALIGNED_64 (msg))
	{
	  /* the most common case is processing of an already aligned message
	     without copying it */
	  aligned_message_block = (uint64_t *) msg;
	}
      else
	{
	  memcpy (ctx->message, msg, block_size);
	  aligned_message_block = ctx->message;
	}

      sha3_process_block (ctx->hash, aligned_message_block);
      msg += block_size;
      size -= block_size;
    }
  if (size)
      memcpy (ctx->message, msg, size);	/* save leftovers */
}


void
sha3_final (sha3_ctx * ctx, unsigned char *result)
{
  size_t digest_length = 100 - ctx->block_size / 2;
  const size_t block_size = ctx->block_size;

  if (!(ctx->rest & SHA3_FINALIZED))
    {
      /* clear the rest of the data queue */
      memset ((char *) ctx->message + ctx->rest, 0, block_size - ctx->rest);
      ((char *) ctx->message)[ctx->rest] |= 0x06;
      ((char *) ctx->message)[block_size - 1] |= 0x80;

      /* process final block */
      sha3_process_block (ctx->hash, ctx->message);
      ctx->rest = SHA3_FINALIZED;	/* mark context as finalized */
    }

  if (result)
    me64_to_le_str (result, ctx->hash, digest_length);
}


/**
 ** MAIN
 **/
int
main (int argc, char *argv[])
{
  new_output = stdout;
  new_input = NULL;

  sha3_ctx *CTX = malloc (sizeof (*CTX)); // Allocate memory for context
  int opt_parser;
  int opt_counter = 0;
  bool input = false;
  bool output = false;
  
/* Parsing Options */
  struct option long_options[] = {
    {"input", required_argument, NULL, 'i'},
    {"output", required_argument, NULL, 'o'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
  };

/* Option treatment */
  while ((opt_parser =
	  getopt_long (argc, argv, "ho:i:", long_options, NULL)) != -1)
    {
      switch (opt_parser)
	{
	case 'i':
	  input = true;
	  opt_counter += 2;
	  new_input = fopen (optarg, "rb");
	  if (!new_input)
	    {
	      perror (PROG_NAME);
	      exit (EXIT_FAILURE);
	    }
	  break;

	case 'o':
	  output = true;
	  opt_counter += 2;
	  new_output = fopen (optarg, "w");
	  if (!new_output)
	    {
	      perror (PROG_NAME);
	      exit (EXIT_FAILURE);
	    }
	  break;

	case 'h':
	  usage (EXIT_SUCCESS, PROG_NAME, new_output);
	  break;

	default:
	  usage (EXIT_FAILURE, PROG_NAME, new_output);
	  break;
	}
    }

  /* Check that the MESSAGE is passed in on the command line */
  if (!(optind <= (argc - 1)) && !input)
    {
      fprintf (stderr, "Please specify the message to hash \n");
      usage (EXIT_FAILURE, PROG_NAME, new_output);
    }

  /* Initialise context, set all bits of CTX to 0, and set block size r
   for sha224, block_size is 144 bytes */
  sha3_224_init (CTX); 

  if (input)
    {
      sha3_write_stream (CTX, new_input);
    }
  else
  {
      unsigned char *T = (unsigned char *) argv[optind];
      sha3_update (CTX, T, strlen((char *)T));
    }

  unsigned char *result = malloc (sizeof (unsigned char) * 224);
  sha3_final (CTX, result);
  print_hexa_hash (result, 224, new_output);

  free (CTX);
  free (result);

  if (output)
    fclose (new_output);

  printf("\n");

  return EXIT_SUCCESS;
}
