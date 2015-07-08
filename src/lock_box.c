#include "crypto_box.h"

int main(int argc, char *argv[]) {
  arguments.key_source = RANDOM;
  argp_parse(&argp_parser, argc, argv, 0, 0, &arguments);

  if (sodium_init() == -1) {
    fprintf(stderr, "unable to initialize libsodium\n");
    exit(EXIT_FAILURE);
  }

  key = key_malloc();
  get_key(&arguments, key);

  FILE *input = open_input(&arguments);
  lock_box(input, stdout);
  close_input(input);

  return EXIT_SUCCESS;
}
// vim: et:ts=2:sw=2
