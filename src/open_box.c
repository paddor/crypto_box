#include "crypto_box.h"
#include "key.h"
#include "decryption.h"

int main(int argc, char *argv[])
{
  arguments.key_source = CMD;
  argp_parse(&argp_parser, argc, argv, 0, 0, &arguments);
  if (arguments.key_source == RANDOM) {
    fprintf(stderr, "Key can't be random while opening a box");
    exit(EXIT_FAILURE);
  }

  crypto_box_init();
  key = key_malloc();
  get_key(&arguments, key);

  FILE *input = open_input(&arguments);
  open_box(input, stdout);
  close_input(input);

  return EXIT_SUCCESS;
}
// vim: et:ts=2:sw=2
