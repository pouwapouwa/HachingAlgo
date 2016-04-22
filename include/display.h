/*
 *
 */

#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>
#include <inttypes.h>
#include <string.h>

/* An int can only be 16 bits long at radix 2 (binary) the string
   is at most 16 + 1 null long.*/
#define BUFFER_SIZE 17


/**
 * MACRO
 **/

/* Rotate left 32 bits values (words) */
#define ROTATE_LEFT(w,s) ((w << s) | (w >> (32 - s)))
#define SWAP_BYTE_ORDER(w) (((w << 24) & 0xff000000) | ((w << 8) & 0x00ff0000)	| ((w >> 8) & 0xff0000ff00) | ((w >> 24) & 0xff000000ff))


/**
 * Functions Available
 **/

char *get_all_args (char **, int, int);
char *itoa (int, char *, int);
void print_binary_char (unsigned char, FILE *);
void print_hexa_hash (unsigned char *, int, FILE *);
void usage (int, char*, FILE *);

#endif /* DISPLAY_H */
