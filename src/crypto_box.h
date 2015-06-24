#ifndef CRYPTO_BOX_H
#define CRYPTO_BOX_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
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

typedef struct {
  uint8_t *data;
  size_t used;
  size_t size;
} ct_t;

static uint8_t key[KEY_BYTES];
static uint8_t nonce[NONCE_BYTES];
static ct_t ct;
static enum { BIN, HEX } ciphertext = BIN;
static enum { RANDOM, CMD, ASK } key_source = RANDOM;

void init_ct(ct_t *ct);
void grow_ct(size_t nbytes_coming);
void free_ct(ct_t *ct);
void cleanup(void);
void get_key(const char * argv[]);
void parse_options(int argc, const char *argv[]);
void hexDump (const char *desc, const void *addr, size_t len);
// vim: et:ts=2:sw=2
#endif
