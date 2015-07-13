#ifndef CRYPTO_BOX_H
#define CRYPTO_BOX_H

#include "config.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h> // for open()
#include <sys/stat.h>
#include <sodium.h>
#include <argp.h>

struct arguments {
  enum { STDIN, INPUT_FILE } input_source;
  enum { BIN, HEX } ct_format;
  enum { RANDOM, KEY_FILE, CMD, ASK } key_source;
  char *key;
  char *key_file;
  char *input_file;
};

/* argument parsing */
extern struct argp argp_parser;
struct arguments arguments;

// vim: et:ts=2:sw=2
#endif
