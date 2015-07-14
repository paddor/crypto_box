#include "config.h"
#include "arguments.h"
#include "key.h"
#include "encryption.h"
#include "util.h"
#include <sodium.h>

static uint8_t *key;

static void cleanup(void)
{
  sodium_free(key);
}

int main(int argc, char *argv[])
{
  arguments.key_source = RANDOM;
  argp_parse(&argp_parser, argc, argv, 0, 0, &arguments);

  crypto_box_init();
  atexit(cleanup);
  key_malloc(&key);
  get_key(&arguments, key);

  FILE *input = open_input(&arguments);
  lock_box(input, stdout, key, arguments.ct_format == HEX);
  close_input(input);

  return EXIT_SUCCESS;

abort:
  return EXIT_FAILURE;
}
// vim: et:ts=2:sw=2
