#include "util.h"

void crypto_box_init(void) {
  if (sodium_init() == -1) {
    fprintf(stderr, "unable to initialize libsodium\n");
    exit(EXIT_FAILURE);
  }
}

FILE*
open_input(struct arguments *arguments)
{
  if (arguments->input_source == INPUT_FILE) {
    FILE *input = fopen(arguments->input_file, "r");
    if (input == NULL) {
      perror("Couldn't open input file");
      exit(EXIT_FAILURE);
    }
    return input;
  } else {
    return stdin;
  }
}

void
close_input(FILE *input)
{
  if (input == stdin) return;
  fclose(input);
}

/* TODO: Remove when libsodium 1.0.4 is out */
void
sodium_increment(unsigned char *n, const size_t nlen)
{
    size_t       i;
    unsigned int c = 1U << 8;

    for (i = (size_t) 0U; i < nlen; i++) {
        c >>= 8;
        c += n[i];
        n[i] = (unsigned char) c;
    }
}

// vim: et:ts=2:sw=2
