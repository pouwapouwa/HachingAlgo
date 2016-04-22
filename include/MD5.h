/*
 * Implementation of the md5 algorithm described in RFC1321
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

#ifndef MD5_H
#define MD5_H

#define PROG_NAME "MD5"
#define MD5_BUFFER 1024
#define DIGEST_SIZE 128

/**
 * MD5 Algorithm context.
 **/

typedef unsigned int md5_size;

/* MD5 context */
struct md5_ctx
{
  struct
  {
    unsigned int A, B, C, D;	/* registers */
  } IHV;
  unsigned char *buf;
  uint8_t size;
  md5_size bits;
};

/**
 * MACRO
 **/

/* Basic md5 functions */
#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (~z & y))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | ~z))
#define FF(a,b,c,d,m,s,t) (a = b + ROTATE_LEFT((a + F(b,c,d) + m + t), s))
#define GG(a,b,c,d,m,s,t) (a = b + ROTATE_LEFT((a + G(b,c,d) + m + t), s))
#define HH(a,b,c,d,m,s,t) (a = b + ROTATE_LEFT((a + H(b,c,d) + m + t), s))
#define II(a,b,c,d,m,s,t) (a = b + ROTATE_LEFT((a + I(b,c,d) + m + t), s))

/**
 * Functions Available
 **/

/* Calculate md5 on a short memory space  */
unsigned char *md5 (unsigned char *, md5_size, unsigned char *);
/* Initilize context structure for md5 */
void md5_init (struct md5_ctx *);
/* Calculate Message Hash  */
void md5_update (struct md5_ctx *);
/* End of the Hashing, storing the hash */
void md5_final (unsigned char *, struct md5_ctx *);

#endif /* MD5_H */
