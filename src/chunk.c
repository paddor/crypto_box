#include "chunk.h"

static void
hex_ct_malloc(uint8_t ** const hex_buf)
{
  *hex_buf = sodium_malloc(CHUNK_CT_BYTES * 2 + 1);
  if (*hex_buf != NULL) return;

  errx(EX_OSERR, "Couldn't allocate memory for hex ciphertexts.");
}

/* allocate memory for authentication subkey */
static void
auth_subkey_malloc(unsigned char ** const subkey)
{
  *subkey = sodium_malloc(crypto_onetimeauth_KEYBYTES);
  if (*subkey != NULL) return;

  errx(EX_OSERR, "Memory for authentication subkey couldn't be allocated.");
}

void
chunk_malloc(struct chunk ** const chunk, bool hex)
{
  *chunk = malloc(sizeof(struct chunk));
  if (*chunk == NULL) errx(EX_OSERR, "Chunk couldn't be allocated");

  (*chunk)->size = 0;
  (*chunk)->used = 0;
  (*chunk)->is_first_chunk = true;
  (*chunk)->hex_buf = NULL;
  (*chunk)->subkey = NULL;

  /* we allocate CHUNK_CT_BYTES, which is the maximum of data needed, and
   * slightly bigger than CHUNK_PT_BYTES
   */
  (*chunk)->data = malloc(CHUNK_CT_BYTES);
  if ((*chunk)->data == NULL) errx(EX_OSERR, "Chunk data couldn't be allocated");
  (*chunk)->size = CHUNK_CT_BYTES;

  /* memory for authentication subkeys */
  auth_subkey_malloc(&(*chunk)->subkey);

  /* allocate memory for hex ciphertexts */
  if(hex) hex_ct_malloc(&(*chunk)->hex_buf);
}

void
chunk_free(struct chunk * const chunk)
{
  free(chunk->data);
  sodium_free(chunk->hex_buf);
  sodium_free(chunk->subkey);
  free(chunk);
}

static uint8_t
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
      chunk_type = CHUNK_TYPE_LAST;
    } else {
      /* not the last chunk, put character back */
      if (ungetc(c, input) == EOF)
        errx(EX_IOERR, "Couldn't put character back.");

      /* might be the first */
      if (chunk->is_first_chunk) chunk_type = CHUNK_TYPE_FIRST;
    }
  } else if (feof(input)) { /* already hit EOF */
     /* this is the last chunk */
    chunk_type = CHUNK_TYPE_LAST;
  } else if (chunk->is_first_chunk) {
    /* Since fread() guarantees that it reads the specified number of bytes
     * if possible, this code should never be reached. If fread() read less
     * bytes, it must have hit EOF already, which is handled above.
     *
     * But what the hell. Better be safe.
     */
    chunk_type = CHUNK_TYPE_FIRST;
  }
  return chunk_type;
}

uint8_t
determine_pt_chunk_type(struct chunk const * const chunk, FILE *input)
{
  return determine_chunk_type(chunk, CHUNK_PT_BYTES, input);
}

uint8_t
determine_ct_chunk_type(struct chunk const * const chunk, FILE *input)
{
  return determine_chunk_type(chunk, CHUNK_CT_BYTES, input);
}

// vim: et:ts=2:sw=2
