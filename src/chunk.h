#ifndef CHUNK_H
#define CHUNK_H
#include "config.h"
#include <err.h>
#include <sysexits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <sodium.h>

/* +- 1 because of the chunk_type */
#define CHUNK_MAC(x) (x)
#define CHUNK_PT(x) (x + crypto_onetimeauth_BYTES + 1)
#define CHUNK_PT_LEN(x) (x - crypto_onetimeauth_BYTES - 1)
#define CHUNK_CT(x) (x + crypto_onetimeauth_BYTES)
#define CHUNK_CT_LEN(x) (x - crypto_onetimeauth_BYTES)
#define CHUNK_TYPE_INDEX crypto_onetimeauth_BYTES
#define CHUNK_CT_BYTES 65536UL /* 64 KiB */
#define CHUNK_PT_BYTES (CHUNK_CT_BYTES - crypto_onetimeauth_BYTES - 1)
#define CHUNK_TYPE_FIRST 1U
#define CHUNK_TYPE_LAST  2U

struct chunk {
  uint8_t *data; /* MAC + chunk_type + {PT,CT} */
  size_t used;
  size_t size;
  _Bool is_first_chunk;
  uint8_t *hex_buf;
  unsigned char *subkey;
};

extern void chunk_malloc(struct chunk ** const chunk, _Bool hex);
extern void chunk_free(struct chunk * const chunk);
extern uint8_t determine_pt_chunk_type(struct chunk const * const, FILE *input);
extern uint8_t determine_ct_chunk_type(struct chunk const * const, FILE *input);

// vim: et:ts=2:sw=2
#endif
