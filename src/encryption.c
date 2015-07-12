#include "encryption.h"

static int
print_nonce(uint8_t const * const nonce, uint8_t *hex_buf, FILE *output)
{
  if (hex_buf == NULL) {
    if (fwrite(nonce, NONCE_BYTES, 1, output) < 1) {
      perror("Couldn't write ciphertext");
      return -1;
    }
  } else {
    char *hex_result; /* result of bin->hex conversion */
    hex_result = sodium_bin2hex((char *) hex_buf, 2 * NONCE_BYTES + 1,
        nonce, NONCE_BYTES);
    if (hex_result == NULL) {
      fprintf(stderr, "Couldn't convert nonce to hex.\n");
      return -1;
    }
    if (fwrite(hex_buf, 2 * NONCE_BYTES, 1, output) < 1) {
      perror("Couldn't write ciphertext");
      return -1;
    }
  }
  return 0;
}

static int
read_pt_chunk(struct chunk * const chunk, FILE *input)
{
  size_t nread = fread(&chunk->data[chunk->used], sizeof *chunk->data,
      CHUNK_PT_BYTES, input);
  chunk->used += nread;
  if (nread < CHUNK_PT_BYTES && ferror(input)) {
    fprintf(stderr, "Couldn't read plaintext.\n");
    return -1;
  }
  DEBUG_ONLY(hexDump("read plaintext chunk",
        CHUNK_PT(chunk->data), CHUNK_PT_LEN(chunk->used)));
  return 0;
}

static void
construct_chunk_mac(
    struct chunk const * const chunk,
    uint8_t const * const nonce,
    uint8_t const * const key)
{
  static unsigned char previous_mac[MAC_BYTES];
  crypto_onetimeauth_state auth_state;

  crypto_stream(chunk->subkey, crypto_onetimeauth_KEYBYTES, nonce, key);
  crypto_onetimeauth_init(&auth_state, chunk->subkey);
  crypto_onetimeauth_update(&auth_state, CHUNK_CT(chunk->data),
      CHUNK_CT_LEN(chunk->used));
  if (!chunk->is_first_chunk) {
    /* include previous MAC */
    crypto_onetimeauth_update(&auth_state, previous_mac, MAC_BYTES);
  }
  crypto_onetimeauth_final(&auth_state, CHUNK_MAC(chunk->data));

  /* remember MAC */
  memcpy(previous_mac, CHUNK_MAC(chunk->data), MAC_BYTES);

  DEBUG_ONLY(hexDump("chunk MAC", CHUNK_MAC(chunk->data), MAC_BYTES));
}

static int
print_ct_chunk(
  struct chunk const * const chunk,
  FILE *output)
{
  if (chunk->hex_buf == NULL) {
    if (fwrite(chunk->data, chunk->used, 1, output) < 1) {
      perror("Couldn't write ciphertext");
      return -1;
    }
  } else {
    char *hex_result; /* result of bin->hex conversion */
    hex_result = sodium_bin2hex((char *) chunk->hex_buf, 2 * chunk->used + 1,
        chunk->data, chunk->used);
    if (hex_result == NULL) {
      fprintf(stderr, "Couldn't convert ciphertext to hex.\n");
      return -1;
    }
    if (fwrite(chunk->hex_buf, chunk->used * 2, 1, output) < 1) {
      perror("Couldn't write ciphertext");
      return -1;
    }
  }
  return 0;
}

static int
encrypt_next_chunk(
    struct chunk *chunk,
    uint8_t * const nonce,
    uint8_t const * const key,
    FILE *input,
    FILE *output)
{
  int8_t chunk_type; /* first, last or in between */

  /* recycle chunk data */
  chunk->used = MAC_BYTES + 1; /* reserve room for MAC + chunk_type */

  /* read complete chunk, if possible */
  if(read_pt_chunk(chunk, input) == -1) return -1;

  chunk_type = determine_chunk_type(chunk, CHUNK_PT_BYTES, input);
  if (chunk_type == -1) return -1;

  /* set chunk type */
  chunk->data[CHUNK_TYPE_INDEX] = chunk_type;
  DEBUG_ONLY(hexDump("chunk type", chunk->data[CHUNK_TYPE_INDEX], 1));

  /* encrypt chunk_type and plaintext (in-place) */
  crypto_stream_xsalsa20_xor_ic(CHUNK_CT(chunk->data), CHUNK_CT(chunk->data),
      CHUNK_CT_LEN(chunk->used), nonce, 1, key); /* 1 = initial counter */
  DEBUG_ONLY(hexDump("ciphertext chunk", CHUNK_CT(chunk->data),
        CHUNK_CT_LEN(chunk->used)));

  /* compute MAC */
  construct_chunk_mac(chunk, nonce, key);

  /* print MAC + chunk_type + ciphertext */
  if (print_ct_chunk(chunk, output) == -1) return -1;

  /* increment nonce */
  sodium_increment(nonce, NONCE_BYTES);

  return 0;
}

void
lock_box(FILE *input, FILE *output)
{
  uint8_t nonce[NONCE_BYTES];
  struct chunk *chunk = NULL;

  /* initialize chunk */
  if (chunk_malloc(&chunk) == -1) goto abort;

  /* ciphertext to TTY warning */
  if (isatty(fileno(output)) && arguments.ct_format == BIN)
    fprintf(stderr, "WARNING: Writing binary ciphertext to terminal.\n");

  /* new nonce */
  randombytes_buf(nonce, sizeof nonce);
  DEBUG_ONLY(hexDump("nonce", nonce, sizeof nonce));

  /* print nonce */
  if (print_nonce(nonce, chunk->hex_buf, output) == -1) goto abort;

  /* encrypt first chunk */
  if (encrypt_next_chunk(chunk, nonce, key, input, output) == -1) goto abort;

  /* encrypt remaining chunks */
  chunk->is_first_chunk = false; /* not first chunk anymore */
  while (!feof(input)) {
    if (encrypt_next_chunk(chunk, nonce, key, input, output) == -1) goto abort;
  }

  /* cleanup */
  chunk_free(chunk);
  return;

abort: /* error */
  chunk_free(chunk);
  exit(EXIT_FAILURE);
}
// vim: et:ts=2:sw=2
