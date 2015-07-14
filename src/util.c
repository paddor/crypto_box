#include "util.h"

void crypto_box_init(void) {
  if (sodium_init() == -1) errx(EX_SOFTWARE, "Unable to initialize libsodium");
}

FILE*
open_input(struct arguments *arguments)
{
  if (arguments->input_source == INPUT_FILE) {
    FILE *input = fopen(arguments->input_file, "r");
    if (input == NULL) err(EX_NOINPUT, "Couldn't open input file");
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
