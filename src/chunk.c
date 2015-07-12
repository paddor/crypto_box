#include "chunk.h"

int
chunk_malloc(struct chunk ** const chunk)
{
  *chunk = malloc(sizeof(struct chunk));
  if (*chunk == NULL) {
    fprintf(stderr, "chunk couldn't be allocated\n");
    return -1;
  }
  (*chunk)->size = 0;
  (*chunk)->used = 0;
  (*chunk)->is_first_chunk = true;

  /* we allocate CHUNK_CT_BYTES, which is the maximum of data needed, and
   * slightly bigger than CHUNK_PT_BYTES
   */
  (*chunk)->data = malloc(CHUNK_CT_BYTES * sizeof *(*chunk)->data);
  if ((*chunk)->data == NULL) {
    fprintf(stderr, "chunk data couldn't be allocated\n");
    return -1;
  }
  (*chunk)->size = CHUNK_CT_BYTES;

  return 0;
}

void
chunk_free(struct chunk * const chunk)
{
  free(chunk->data);
  free(chunk);
}

int8_t
determine_chunk_type(
    struct chunk const * const chunk,
    size_t chunk_bytes,
    FILE *input)
{
  /* TODO: add determine_ct_chunk_type() and determine_pt_chunk_type() so
   * chunk_bytes doesn't have to be specified at the call site */

  int c;
  uint8_t chunk_type = 0; /* nothing special about this chunk for now */
  if (chunk->used == chunk_bytes) {
    /* check if we're right before EOF */
    if ((c = getc(input)) == EOF) {
      /* this is the last chunk */
      chunk_type = LAST_CHUNK;
    } else {
      /* not the last chunk, put character back */
      if (ungetc(c, input) == EOF) {
        fprintf(stderr, "Couldn't put character back.\n");
        return -1;
      }

      /* might be the first */
      if (chunk->is_first_chunk) chunk_type = FIRST_CHUNK;
    }
  } else if (feof(input)) { /* already hit EOF */
     /* this is the last chunk */
    chunk_type = LAST_CHUNK;
  } else if (chunk->is_first_chunk) {
    /* Since fread() guarantees that it reads the specified number of bytes
     * if possible, this code should never be reached. If fread() read less
     * bytes, it must have hit EOF already, which is handled above.
     *
     * But what the hell. Better be safe.
     */
    chunk_type = FIRST_CHUNK;
  }
  return chunk_type;
}

int
hex_ct_malloc(uint8_t ** const hex_buf)
{
  if (arguments.ct_format != HEX) return 0;

  *hex_buf = sodium_malloc(CHUNK_CT_BYTES * 2 + 1);
  if (*hex_buf != NULL) return 0;

  fprintf(stderr, "Couldn't allocate memory for hex ciphertexts.\n");
  return -1;
}

/* allocate memory for authentication subkey */
int
auth_subkey_malloc(unsigned char ** const subkey)
{
  *subkey = sodium_malloc(crypto_onetimeauth_KEYBYTES);
  if (*subkey == NULL) {
    fprintf(stderr, "Memory for authentication subkey couldn't be "
        "allocated.\n");
    return -1;
  }
  return 0;
}

// vim: et:ts=2:sw=2
