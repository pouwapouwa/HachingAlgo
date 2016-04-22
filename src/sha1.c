/* This code is public-domain - it is based on libcrypt
 * placed in the public domain by Wei Dai and other contributors.
 */

#include "display.h"
#include "SHA1.h"


/**
 ** Variables
 **/


static FILE *new_output;
static FILE *new_input;


/**
 ** code
 **/


void
sha1_init (sha1_ctx * s)
{
  s->state[0] = S0;
  s->state[1] = S1;
  s->state[2] = S2;
  s->state[3] = S3;
  s->state[4] = S4;
  
  s->byteCount = 0;
  s->bufferOffset = 0;
}


void
sha1_hashBlock (sha1_ctx * s)
{
  uint8_t t;
  uint32_t a, b, c, d, e, t2;

  a = s->state[0];
  b = s->state[1];
  c = s->state[2];
  d = s->state[3];
  e = s->state[4];
  /* 80 steps t of the algorithm */
  for (t = 0; t < 80; t++)
  {
    /* There we are working on 16 states, instead of 80*/ 
    if (t >= 16)
    {
      t2 =
	s->buffer[(t + 13) & 15] ^ s->buffer[(t + 8) & 15] ^ s->
	buffer[(t + 2) & 15] ^ s->buffer[t & 15];
      s->buffer[t & 15] = ROTATE_LEFT (t2, 1);
    }
    /* There are different functions, dependign of the step t */
    if (t < 20)
      t2 = (d ^ (b & (c ^ d))) + AC0;	//F
    else if (t < 40)
      t2 = (b ^ c ^ d) + AC20;	//G
    else if (t < 60)
      t2 = ((b & c) | (d & (b | c))) + AC40;	//H
    else
      t2 = (b ^ c ^ d) + AC60;	//I
    t2 += ROTATE_LEFT (a, 5) + e + s->buffer[t & 15];
    /* Rotation of working values */
    e = d;
    d = c;
    c = ROTATE_LEFT (b, 30);
    b = a;
    a = t2;
  }
  /* Final Hash for this Block */
  s->state[0] += a;
  s->state[1] += b;
  s->state[2] += c;
  s->state[3] += d;
  s->state[4] += e;
}


void
sha1_addUncounted (sha1_ctx * s, uint8_t data)
{
  uint8_t *const b = (uint8_t *) s->buffer;

  /* To pass it in Little endian */
  b[s->bufferOffset ^ 3] = data;
  s->bufferOffset++;
    
  if (s->bufferOffset == BLOCK_LENGTH)
  {
    sha1_hashBlock (s);
    s->bufferOffset = 0;
  }
}


void
sha1_write_byte (sha1_ctx * s, uint8_t data)
{
  ++(s->byteCount);
  sha1_addUncounted (s, data);
}


void
sha1_write (sha1_ctx * s, uint8_t *data, size_t len)
{
    int i;
  for (i = 0; len--;i++)
    sha1_write_byte (s, data[i]);
}

void
sha1_write_stream (sha1_ctx * s, FILE * f)
{
  bool end = false;
  do
  {
      int i;
    uint8_t tmp[64];
    for (i = 0; i < 64; i++)
      tmp[i] = 0;
   
    // Read data
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
    // Write data in the strcut sha1_ctx, and hash it if possible
    sha1_write (s, tmp2, size);
    free (tmp2);
  }
  while (!end);
}

void
sha1_pad (sha1_ctx * s)
{
// Pad with 0x80 followed by 0x00 until the end of the block
  sha1_addUncounted (s, 0x80);
  while (s->bufferOffset != 56)
    sha1_addUncounted (s, 0x00);

// Append length in the last 8 bytes
  sha1_addUncounted (s, 0);	// We're only using 32 bit lengths
  sha1_addUncounted (s, 0);	// But SHA-1 supports 64 bit lengths
  sha1_addUncounted (s, 0);	// So zero pad the top bits

// Previous zero will "overlap" last 3 bytes of the length
  sha1_addUncounted (s, s->byteCount >> 29);    
  sha1_addUncounted (s, s->byteCount >> 21);    
  sha1_addUncounted (s, s->byteCount >> 13);    
  sha1_addUncounted (s, s->byteCount >> 5);
  sha1_addUncounted (s, s->byteCount << 3); //This one should trigger sha1 hash
}


uint8_t *
sha1_result (sha1_ctx * s)
{
// Pad to complete the last block
  sha1_pad (s);

// Swap byte order back
  int i;
  for (i = 0; i < 5; i++)
    s->state[i] = SWAP_BYTE_ORDER (s->state[i]);
    
// Return pointer to hash (20 characters)
  return (uint8_t *) s->state;
}


/**
 **MAIN 
 **/
int
main (int argc, char **argv)
{
  new_output = stdout;
  new_input = NULL;

  sha1_ctx s;
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
  
  if (input)
  {
    sha1_init (&s);
    sha1_write_stream (&s, new_input);
  }
  else
  {
    uint8_t * tmp = malloc (sizeof (uint8_t) * (strlen (argv[optind]) + 1));
    memcpy (tmp, argv[optind], strlen (argv[optind]) + 1);
    sha1_init (&s);
    sha1_write (&s, tmp, strlen (argv[optind]));
    free (tmp);
  }

  /* Print in hexadecimal format */
  print_hexa_hash ((unsigned char *) sha1_result (&s), DIGEST_SIZE*4, new_output);
  
  if (output)
    fclose (new_output);

  printf("\n");
  
  return 0;
}
