#ifndef ARGUMENTS_H
#define ARGUMENTS_H
#include "config.h"
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
