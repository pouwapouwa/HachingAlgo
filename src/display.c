#include "display.h"

#include <unistd.h>

char *
get_all_args (char *args[], int argc, int numb)
{
  unsigned int sum = 0;
  int i;
  for (i = 0; i < numb; i++)
    sum += strlen (args[argc - numb + i]);

  char *tmp = malloc (sizeof (char) * (sum + argc - 1));
  sum = strlen (args[argc - numb]);
  memcpy (tmp, args[argc - numb], sum);

  if (argc > 2)
    {
      for (i = argc - numb + 1; i < argc; i++)
	{
	  memcpy (tmp + sum, " ", 1);
	  memcpy (tmp + sum + 1, args[i], strlen (args[i]));
	  sum += strlen (args[i]) + 1;
	}
    }
  memcpy (tmp + sum, "\0", 1);

  return tmp;
}

char *
itoa (int num, char *str, int base)
{
  char sign = 0;
  char temp[BUFFER_SIZE];	//an int can only be 16 bits long
  //at base 2 (binary) the string
  //is at most 16 + 1 null long.
  int temp_loc = 0;
  int digit;
  int str_loc = 0;

  //save sign for base 10 conversion
  if (base == 10 && num < 0)
    {
      sign = 1;
      num = -num;
    }

  //construct a backward string of the number.
  do
    {
      digit = (unsigned int) num % base;
      if (digit < 10)
	temp[temp_loc++] = digit + '0';
      else
	temp[temp_loc++] = digit - 10 + 'A';
      num = (((unsigned int) num) / base);
    }
  while ((unsigned int) num > 0);

  //now add the sign for base 10
  if (base == 10 && sign)
    {
      temp[temp_loc] = '-';
    }
  else
    {
      temp_loc--;
    }


  //now reverse the string.
  int pad_length = 7 - temp_loc;
  while (pad_length > 0)
    {				// while there are still chars
      str[str_loc++] = '0';
      pad_length--;
    }
  while (temp_loc >= 0)
    {				// while there are still chars
      str[str_loc++] = temp[temp_loc--];
    }
  str[str_loc] = 0;		// add null termination.
  return str;
}

void
print_binary_char (unsigned char character, FILE * out_put)
{
  char output[9];
  itoa (character, output, 2);
  fprintf (out_put, "%s", output);
}

void
print_hexa_hash (unsigned char *hash, int hash_size_in_bits, FILE * output)
{
  char *converted = malloc (sizeof (char) * hash_size_in_bits / 4 + 1);
  int i;
  for (i = 0; i < hash_size_in_bits / 8; i++)
    sprintf (&converted[i * 2], "%02x", hash[i]);

  fprintf (output, "%s", converted);
  free (converted);
}

void
usage (int status, char *name, FILE * output)
{
  if (status == EXIT_SUCCESS)
    {
      fprintf (output, "Usage : %s [OPTION] MESSAGE\n"
	       "Produce %s hash for message.\n"
	       "\t -i,  --input           choose a file as input of the hash\n"
	       "\t -o,  --output          choose a file as output of the hash\n"
	       "\t -h,  --help            display this help\n", name, name);
    }
  else
    fprintf (stderr, "Try '%s --help' for more information.\n", name);
  exit (status);
}
