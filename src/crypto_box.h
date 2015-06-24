#ifndef CRYPTO_BOX_H
#define CRYPTO_BOX_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sodium.h>

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

typedef enum { BIN, HEX } ct_format_t;
typedef enum { RANDOM, CMD, ASK } key_source_t;

extern void init_ct(ct_t *ct);
extern void grow_ct(ct_t *ct, size_t nbytes_coming);
extern void free_ct(ct_t *ct);
extern void get_key(const key_source_t key_source,
    uint8_t key[KEY_BYTES], const char * argv[]);
extern void get_key_from_args(uint8_t *key, const char * argv[]);
extern void parse_options(key_source_t *key_source,
    ct_format_t *ct_format, int argc, const char *argv[]);
extern void hexDump (const char *desc, const void *addr, size_t len);
// vim: et:ts=2:sw=2
#endif
