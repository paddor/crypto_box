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

#ifdef DEBUG
  #define DEBUG_ONLY(x) (x)
#else
  #define DEBUG_ONLY(x)
#endif

#define KEY_BYTES crypto_stream_xsalsa20_KEYBYTES
#define NONCE_BYTES crypto_stream_xsalsa20_NONCEBYTES
#define MAC_BYTES crypto_onetimeauth_BYTES

/* +- 1 because of the chunk_type */
#define CHUNK_MAC(x) (x)
#define CHUNK_PT(x) (x + MAC_BYTES + 1)
#define CHUNK_PT_LEN(x) (x - MAC_BYTES - 1)
#define CHUNK_CT(x) (x + MAC_BYTES)
#define CHUNK_CT_LEN(x) (x - MAC_BYTES)
#define CHUNK_TYPE_INDEX MAC_BYTES
#define CHUNK_CT_BYTES 262144 /* 256 KiB */
#define CHUNK_PT_BYTES (CHUNK_CT_BYTES - MAC_BYTES - 1) /* 256 KiB - 17 */
#define FIRST_CHUNK 1U
#define LAST_CHUNK  2U

struct chunk {
  uint8_t *data; /* MAC + chunk_type + {PT,CT} */
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

extern struct argp argp_parser;
struct arguments arguments;
uint8_t *key;
extern void init_chunk(struct chunk *chunk);
extern void free_chunk(struct chunk *chunk);
extern unsigned char *auth_subkey_malloc();
extern int8_t determine_chunk_type(size_t nread, size_t chunk_bytes, _Bool
    is_first_chunk, FILE *input);
extern void get_key(const struct arguments * const arguments, uint8_t
    key[KEY_BYTES]);
extern uint8_t *key_malloc();
extern FILE* open_input(struct arguments *arguments);
extern void close_input(FILE *input);
void lock_box(FILE *input, FILE *output);
void open_box(FILE *input, FILE *output);
extern void hexDump (const char *desc, const void *addr, size_t len);

/* TODO: Remove when libsodium 1.0.4 is out */
extern void sodium_increment(unsigned char *n, const size_t nlen);
// vim: et:ts=2:sw=2
#endif
