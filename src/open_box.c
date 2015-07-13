#include "crypto_box.h"
#include "key.h"
#include "decryption.h"
#include "util.h"

static uint8_t *key;

static void cleanup(void)
{
  sodium_free(key);
}

int main(int argc, char *argv[])
{
  arguments.key_source = CMD;
  argp_parse(&argp_parser, argc, argv, 0, 0, &arguments);
  if (arguments.key_source == RANDOM) {
    fprintf(stderr, "Key can't be random while opening a box");
    exit(EXIT_FAILURE);
  }

  crypto_box_init();
  atexit(cleanup);
  if (key_malloc(&key) == -1) goto abort;
  get_key(&arguments, key);

  FILE *input = open_input(&arguments);
  open_box(input, stdout, key);
  close_input(input);

  return EXIT_SUCCESS;

abort:
  return EXIT_FAILURE;
}
// vim: et:ts=2:sw=2
