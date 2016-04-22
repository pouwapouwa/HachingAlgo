/* $Id: md5.c,v 1.3 2006-05-01 16:57:31 quentin Exp $ */

/*
 * Implementation of the md5 algorithm as described in RFC1321
 * Copyright (C) 2005 Quentin Carbonneaux <crazyjoke@free.fr>
 *
 * This file is part of md5sum.
 *
 * md5sum is a free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Softawre Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * md5sum is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should hav received a copy of the GNU General Public License
 * along with md5sum; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "display.h"
#include "MD5.h"

#include <math.h>

/* Rotation constants */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21


//#define memcopy(a,b,c) md5_memcopy ((a), (b), (c))
//#define memset(a,b,c) md5_memset ((a), (b), (c))

#define GET_UINT32(a,b,i)			\
  {						\
    (a) = ( (unsigned int) (b)[(i)  ]      )	\
      | ( (unsigned int) (b)[(i)+1] << 8 )	\
      | ( (unsigned int) (b)[(i)+2] << 16)	\
      | ( (unsigned int) (b)[(i)+3] << 24);	\
  }

/* local functions */
static unsigned int AC (int);
static void md5_memset (unsigned char *, const unsigned char,
			const unsigned int);
static void md5_addsize (unsigned char *, md5_size, md5_size);
static void md5_encode (unsigned char *, struct md5_ctx *);

static unsigned char MD5_PADDING[64] = {	/* 512 Bits */
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static FILE *new_output;
static FILE *new_input;

/*
 * An easy way to do the md5 sum of a short memory space
 */
unsigned char *
md5 (unsigned char *M, md5_size len, unsigned char *_digest)
{
  int buflen = (len > MD5_BUFFER) ? MD5_BUFFER : len;
  struct md5_ctx *context;

  context = malloc (sizeof (struct md5_ctx));
  context->buf = malloc (buflen);
  context->size = 0;
  context->bits = 0;

  /* Init registries */
  context->IHV.A = 0x67452301;
  context->IHV.B = 0xefcdab89;
  context->IHV.C = 0x98badcfe;
  context->IHV.D = 0x10325476;

  do
  {
    memcpy (context->buf + context->size, M + context->bits,
	     buflen - context->size);
    context->size += buflen - context->size;
    md5_update (context);
  }
  while (len - context->bits > 64);

  md5_final (_digest, context);

  free (context->buf);
  free (context);

  return _digest;
}

void
md5_init (struct md5_ctx *context)
{
  context->buf = malloc (MD5_BUFFER);

  md5_memset (context->buf, '\0', MD5_BUFFER);
  context->size = 0;
  context->bits = 0;

  /* Init registries */
  context->IHV.A = 0x67452301;
  context->IHV.B = 0xefcdab89;
  context->IHV.C = 0x98badcfe;
  context->IHV.D = 0x10325476;
}

/* md5_size is bytes while the size at the end of the message is in bits ... */
static void
md5_addsize (unsigned char *M, md5_size index, md5_size oldlen)
{
  M[index++] = (unsigned char) ((oldlen << 3) & 0xFF);
  M[index++] = (unsigned char) ((oldlen >> 5) & 0xFF);
  M[index++] = (unsigned char) ((oldlen >> 13) & 0xFF);
  M[index++] = (unsigned char) ((oldlen >> 21) & 0xFF);
  /* Fill with 0 because md5_size is 32 bits long */
  M[index++] = 0;
  M[index++] = 0;
  M[index++] = 0;
  M[index++] = 0;
}

/*
 * Update a context by concatenating a new block
 */
void
md5_update (struct md5_ctx *context)
{
  unsigned char buffer[64];	/* 512 bits */
  int i;
  /*M0 a Mn-1 */
  for (i = 0; context->size - i > 63; i += 64)
  {
    memcpy (buffer, context->buf + i, 64);
    md5_encode (buffer, context);
    context->bits += 64;
  }
  memcpy (buffer, context->buf + i, context->size - i);
  memcpy (context->buf, buffer, context->size - i);
  context->size -= i;
}

void
md5_update_file (struct md5_ctx *context, FILE * f)
{
  uint8_t buffer[64];	/* 512 bits */
  size_t size = 0;
  unsigned int i = 0;
  while ((size = fread (buffer, sizeof (uint8_t), 64, f)) == 64)
  {
    md5_encode (buffer, context);
    context->size -= 64;
    context->bits += 64;
    i++;
  }
  context->size = size;
  memcpy (context->buf, buffer, size);
}

void
md5_final (unsigned char *digest, struct md5_ctx *context)
{
  unsigned char buffer[64];	/* 512 bits */
  int i;

  if (context->size + 1 > 56)
  {				
/* We have to create another block */
    memcpy (buffer, context->buf, context->size);
    memcpy (buffer + context->size, MD5_PADDING, 64 - context->size);
    md5_encode (buffer, context);
    context->bits += context->size;
    context->size = 0;
    /* Proceed final block */
    memset (buffer, '\0', 56);
    md5_addsize (buffer, 56, context->bits);
    md5_encode (buffer, context);
  }
  else
  {    
    memcpy (buffer, context->buf, context->size);
    context->bits += context->size;
    memcpy (buffer + context->size, MD5_PADDING, 56 - context->size);
    md5_addsize (buffer, 56, context->bits);
    md5_encode (buffer, context);
  }

  // Since this implementation uses little endian byte ordering and MD uses big endian, 
  // reverse all the bytes when copying the final state to the output hash. 
  /* update digest */
  for (i = 0; i < 4; i++)
    digest[i] = (unsigned char) ((context->IHV.A >> (i * 8)) & 0xFF);
  for (; i < 8; i++)
    digest[i] = (unsigned char) ((context->IHV.B >> ((i - 4) * 8)) & 0xFF);
  for (; i < 12; i++)
    digest[i] = (unsigned char) ((context->IHV.C >> ((i - 8) * 8)) & 0xFF);
  for (; i < 16; i++)
    digest[i] = (unsigned char) ((context->IHV.D >> ((i - 12) * 8)) & 0xFF);
}

/* Calculate ACt*/
static unsigned int
AC (int t)
{
  return floor (fabs (sin (t + 1)) * pow (2, 32));
}

/* Expand the message word M into Wt for each step*/
static int
msgexp (int t, int r)
{
  switch (r)
  {
  case 1:
    return ((1 + 5 * t) % 16);
    break;
  case 2:
    return ((5 + 3 * t) % 16);
    break;
  case 3:
    return ((7 * t) % 16);
    break;
  default:
    return EXIT_FAILURE;
  }
}

/*Compression function*/
static void
md5_encode (unsigned char *buffer, struct md5_ctx *context)
{
  unsigned int a = context->IHV.A, b = context->IHV.B, c =
    context->IHV.C, d = context->IHV.D;
  unsigned int m[16];

/* Little endian format*/
  GET_UINT32 (m[0], buffer, 0); 
  GET_UINT32 (m[1], buffer, 4);
  GET_UINT32 (m[2], buffer, 8);
  GET_UINT32 (m[3], buffer, 12);
  GET_UINT32 (m[4], buffer, 16);
  GET_UINT32 (m[5], buffer, 20);
  GET_UINT32 (m[6], buffer, 24);
  GET_UINT32 (m[7], buffer, 28);
  GET_UINT32 (m[8], buffer, 32);
  GET_UINT32 (m[9], buffer, 36);
  GET_UINT32 (m[10], buffer, 40);
  GET_UINT32 (m[11], buffer, 44);
  GET_UINT32 (m[12], buffer, 48);
  GET_UINT32 (m[13], buffer, 52);
  GET_UINT32 (m[14], buffer, 56);
  GET_UINT32 (m[15], buffer, 60);

  /* Round 0 */
  FF (a, b, c, d, m[0], S11, AC (0));	/* 0 */
  FF (d, a, b, c, m[1], S12, AC (1));	/* 1 */
  FF (c, d, a, b, m[2], S13, AC (2));	/* 2 */
  FF (b, c, d, a, m[3], S14, AC (3));	/* 3 */
  FF (a, b, c, d, m[4], S11, AC (4));	/* 4 */
  FF (d, a, b, c, m[5], S12, AC (5));	/* 5 */
  FF (c, d, a, b, m[6], S13, AC (6));	/* 6 */
  FF (b, c, d, a, m[7], S14, AC (7));	/* 7 */
  FF (a, b, c, d, m[8], S11, AC (8));	/* 8 */
  FF (d, a, b, c, m[9], S12, AC (9));	/* 9 */
  FF (c, d, a, b, m[10], S13, AC (10));	/* 10 */
  FF (b, c, d, a, m[11], S14, AC (11));	/* 11 */
  FF (a, b, c, d, m[12], S11, AC (12));	/* 12 */
  FF (d, a, b, c, m[13], S12, AC (13));	/* 13 */
  FF (c, d, a, b, m[14], S13, AC (14));	/* 14 */
  FF (b, c, d, a, m[15], S14, AC (15));	/* 15 */


  /* Round 1 */
  GG (a, b, c, d, m[msgexp (16, 1)], S21, AC (16));	/* 16 */
  GG (d, a, b, c, m[msgexp (17, 1)], S22, AC (17));	/* 17 */
  GG (c, d, a, b, m[msgexp (18, 1)], S23, AC (18));	/* 18 */
  GG (b, c, d, a, m[msgexp (19, 1)], S24, AC (19));	/* 19 */
  GG (a, b, c, d, m[msgexp (20, 1)], S21, AC (20));	/* 20 */
  GG (d, a, b, c, m[msgexp (21, 1)], S22, AC (21));	/* 21 */
  GG (c, d, a, b, m[msgexp (22, 1)], S23, AC (22));	/* 22 */
  GG (b, c, d, a, m[msgexp (23, 1)], S24, AC (23));	/* 23 */
  GG (a, b, c, d, m[msgexp (24, 1)], S21, AC (24));	/* 24 */
  GG (d, a, b, c, m[msgexp (25, 1)], S22, AC (25));	/* 25 */
  GG (c, d, a, b, m[msgexp (26, 1)], S23, AC (26));	/* 26 */
  GG (b, c, d, a, m[msgexp (27, 1)], S24, AC (27));	/* 27 */
  GG (a, b, c, d, m[msgexp (28, 1)], S21, AC (28));	/* 28 */
  GG (d, a, b, c, m[msgexp (29, 1)], S22, AC (29));	/* 29 */
  GG (c, d, a, b, m[msgexp (30, 1)], S23, AC (30));	/* 30 */
  GG (b, c, d, a, m[msgexp (31, 1)], S24, AC (31));	/* 31 */

  /* Round 2 */
  HH (a, b, c, d, m[msgexp (32, 2)], S31, AC (32));	/* 32 */
  HH (d, a, b, c, m[msgexp (33, 2)], S32, AC (33));	/* 33 */
  HH (c, d, a, b, m[msgexp (34, 2)], S33, AC (34));	/* 34 */
  HH (b, c, d, a, m[msgexp (35, 2)], S34, AC (35));	/* 35 */
  HH (a, b, c, d, m[msgexp (36, 2)], S31, AC (36));	/* 36 */
  HH (d, a, b, c, m[msgexp (37, 2)], S32, AC (37));	/* 37 */
  HH (c, d, a, b, m[msgexp (38, 2)], S33, AC (38));	/* 38 */
  HH (b, c, d, a, m[msgexp (39, 2)], S34, AC (39));	/* 39 */
  HH (a, b, c, d, m[msgexp (40, 2)], S31, AC (40));	/* 40 */
  HH (d, a, b, c, m[msgexp (41, 2)], S32, AC (41));	/* 41 */
  HH (c, d, a, b, m[msgexp (42, 2)], S33, AC (42));	/* 42 */
  HH (b, c, d, a, m[msgexp (43, 2)], S34, AC (43));	/* 43 */
  HH (a, b, c, d, m[msgexp (44, 2)], S31, AC (44));	/* 44 */
  HH (d, a, b, c, m[msgexp (45, 2)], S32, AC (45));	/* 45 */
  HH (c, d, a, b, m[msgexp (46, 2)], S33, AC (46));	/* 46 */
  HH (b, c, d, a, m[msgexp (47, 2)], S34, AC (47));	/* 47 */

  /* Round 3 */
  II (a, b, c, d, m[msgexp (48, 3)], S41, AC (48));	/* 48 */
  II (d, a, b, c, m[msgexp (49, 3)], S42, AC (49));	/* 49 */
  II (c, d, a, b, m[msgexp (50, 3)], S43, AC (50));	/* 50 */
  II (b, c, d, a, m[msgexp (51, 3)], S44, AC (51));	/* 51 */
  II (a, b, c, d, m[msgexp (52, 3)], S41, AC (52));	/* 52 */
  II (d, a, b, c, m[msgexp (53, 3)], S42, AC (53));	/* 53 */
  II (c, d, a, b, m[msgexp (54, 3)], S43, AC (54));	/* 54 */
  II (b, c, d, a, m[msgexp (55, 3)], S44, AC (55));	/* 55 */
  II (a, b, c, d, m[msgexp (56, 3)], S41, AC (56));	/* 56 */
  II (d, a, b, c, m[msgexp (57, 3)], S42, AC (57));	/* 57 */
  II (c, d, a, b, m[msgexp (58, 3)], S43, AC (58));	/* 58 */
  II (b, c, d, a, m[msgexp (59, 3)], S44, AC (59));	/* 59 */
  II (a, b, c, d, m[msgexp (60, 3)], S41, AC (60));	/* 60 */
  II (d, a, b, c, m[msgexp (61, 3)], S42, AC (61));	/* 61 */
  II (c, d, a, b, m[msgexp (62, 3)], S43, AC (62));	/* 62 */
  II (b, c, d, a, m[msgexp (63, 3)], S44, AC (63));	/* 63 */

  context->IHV.A += a;
  context->IHV.B += b;
  context->IHV.C += c;
  context->IHV.D += d;
}

static void
md5_memset (unsigned char *p, const unsigned char c, const unsigned int count)
{
  unsigned int i;

  for (i = 0; i < count; i++)
  {
    p[i] = c;
  }
}

int
main (int argc, char *argv[])
{
  new_output = stdout;
  new_input = NULL;

  /* getopt_long stores the option here. */
  int opt_parser;
  /* getopt_long stores the option index here. */
  int option_index = 0;
  int opt_counter = 0;
  bool input = false;
  bool output = false;

  /* Parse input message M */
  struct option long_options[] = {
    {"length", required_argument, NULL, 'l'},
    {"input", required_argument, NULL, 'i'},
    {"output", required_argument, NULL, 'o'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
  };

  while ((opt_parser = getopt_long (argc, argv, "o:i:l::hM:", long_options,
				    &option_index)) != -1)
  {
    switch (opt_parser)
    {
    case 'i':
      input = true;
      opt_counter += 2;
      new_input = fopen (optarg, "r");
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

      /* help option */
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

  struct md5_ctx ctx;
  unsigned char digest[DIGEST_SIZE / 8];
  md5_init (&ctx);

  if (input)
    md5_update_file (&ctx, new_input);
  else
  {
    size_t size = strlen (argv[optind]);
    uint8_t * msg = malloc (sizeof (uint8_t) * (size + 1));
    memcpy (msg, argv[optind], size + 1);
    
    ctx.size = size;
    memcpy (ctx.buf, msg, ctx.size + 1);
    md5_update (&ctx);
    free (msg);
  }
  md5_final (digest, &ctx);

  /* Print in hexadecimal format */
  print_hexa_hash (digest, DIGEST_SIZE, new_output);
  
  free ((&ctx)->buf);
  
  if (output)
    fclose (new_output);

  printf("\n");

  return EXIT_SUCCESS;
}
