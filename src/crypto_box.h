#ifndef CRYPTO_BOX_H
#define CRYPTO_BOX_H

#include "config.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h> // for open()
#include <sys/stat.h>
#include <sodium.h>
#include <argp.h>

#ifdef DEBUG
  #define DEBUG_ONLY(x) (x)
#else
  #define DEBUG_ONLY(x)
#endif

#define INITIAL_CT_SIZE 512
#define KEY_BYTES crypto_secretbox_KEYBYTES
#define MAC_BYTES crypto_secretbox_MACBYTES
#define NONCE_BYTES crypto_secretbox_NONCEBYTES
#define CT_AFTER_MAC(x) (x+MAC_BYTES)
#define PT_LEN(x) (x-MAC_BYTES)
#define READ_BYTES 128

struct ciphertext {
  uint8_t *data;
  size_t used;
  size_t size;
};

struct arguments {
  enum { STDIN, INPUT_FILE } input_source;
  enum { BIN, HEX } ct_format;
  enum { RANDOM, KEY_FILE, CMD, ASK } key_source;
  char *key;
  char *key_file;
  char *input_file;
};

extern struct argp argp;
uint8_t key[KEY_BYTES];
uint8_t nonce[NONCE_BYTES];
struct ciphertext ct;
extern void init_ct(struct ciphertext *ct);
extern void grow_ct(struct ciphertext *ct, size_t nbytes_coming);
extern void free_ct(struct ciphertext *ct);
extern void get_key(const struct arguments * const arguments, uint8_t key[KEY_BYTES]);
extern void key_mlock(void);
extern FILE* open_input(struct arguments *arguments);
extern void close_input(FILE *input);
extern void hexDump (const char *desc, const void *addr, size_t len);
// vim: et:ts=2:sw=2
#endif
