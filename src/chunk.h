#ifndef CHUNK_H
#define CHUNK_H
#include "crypto_box.h"

/* +- 1 because of the chunk_type */
#define CHUNK_MAC(x) (x)
#define CHUNK_PT(x) (x + MAC_BYTES + 1)
#define CHUNK_PT_LEN(x) (x - MAC_BYTES - 1)
#define CHUNK_CT(x) (x + MAC_BYTES)
#define CHUNK_CT_LEN(x) (x - MAC_BYTES)
#define CHUNK_TYPE_INDEX MAC_BYTES
#define CHUNK_CT_BYTES 262144UL /* 256 KiB */
#define CHUNK_PT_BYTES (CHUNK_CT_BYTES - MAC_BYTES - 1) /* 256 KiB - 17 */
#define FIRST_CHUNK 1U
#define LAST_CHUNK  2U

struct chunk {
  uint8_t *data; /* MAC + chunk_type + {PT,CT} */
  size_t used;
  size_t size;
  _Bool is_first_chunk;
  uint8_t *hex_buf;
  unsigned char *subkey;
};

extern int chunk_malloc(struct chunk ** const chunk);
extern void chunk_free(struct chunk * const chunk);
extern int8_t determine_pt_chunk_type(struct chunk const * const, FILE *input);
extern int8_t determine_ct_chunk_type(struct chunk const * const, FILE *input);

// vim: et:ts=2:sw=2
#endif