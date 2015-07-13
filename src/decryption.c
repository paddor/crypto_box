#include "decryption.h"

static int
read_nonce(uint8_t * const nonce, uint8_t *hex_buf, FILE *input)
{
  size_t bin_len; /* length of binary data written during conversion  */
  int hex_result; /* result of hex->bin conversion */
  if (hex_buf == NULL) {
    if (fread(nonce, NONCE_BYTES, 1, input) < 1) {
      fprintf(stderr, "Couldn't read ciphertext.\n");
      return -1;
    }
  } else {
    if (fread(hex_buf, NONCE_BYTES * 2, 1, input) < 1) {
      fprintf(stderr, "Couldn't read ciphertext.\n");
      return -1;
    }

    hex_result = sodium_hex2bin(nonce, NONCE_BYTES, (const char*) hex_buf,
      NONCE_BYTES * 2, NULL, &bin_len, NULL);
    if (hex_result != 0 || bin_len < NONCE_BYTES) {
      fprintf(stderr, "Couldn't convert to binary ciphertext.\n");
      return -1;
    }
  }
  return 0;
}

static int
read_ct_chunk(struct chunk * const chunk, FILE *input)
{
  if (chunk->hex_buf == NULL) {
    chunk->used = fread(chunk->data, 1, chunk->size, input);
  } else {
    size_t nread = fread(chunk->hex_buf, 2, CHUNK_CT_BYTES, input);
    if (nread < CHUNK_CT_BYTES && ferror(input)) {
      fprintf(stderr, "Couldn't read ciphertext.\n");
      return -1;
    }

    int hex_result; /* result of hex->bin conversion */
    hex_result = sodium_hex2bin(chunk->data, chunk->size,
        (const char*) chunk->hex_buf, nread * 2, NULL, &chunk->used, NULL);
    if (hex_result != 0 || chunk->used < nread) {
      fprintf(stderr, "Couldn't convert to binary ciphertext.\n");
      return -1;
    }
  }

  /* truncated header */
  if (chunk->used < 17) { /* MAC + chunk_type = 17 */
    fprintf(stderr, "Ciphertext's header has been truncated.\n");
    return -1;
  }

  /* read error */
  if (chunk->used < (CHUNK_CT_BYTES) && ferror(input)) {
    fprintf(stderr, "Couldn't read ciphertext.\n");
    return -1;
  }

  return 0;
}

static int
verify_chunk(
    struct chunk const * const chunk,
    uint8_t const * const nonce,
    uint8_t const * const key)
{
  static unsigned char mac[MAC_BYTES];
  crypto_onetimeauth_state auth_state;

  /* derive subkey */
  crypto_stream(chunk->subkey, crypto_onetimeauth_KEYBYTES, nonce, key);

  /* compute MAC */
  crypto_onetimeauth_init(&auth_state, chunk->subkey);
  crypto_onetimeauth_update(&auth_state, CHUNK_CT(chunk->data),
      CHUNK_CT_LEN(chunk->used));
  if (!chunk->is_first_chunk) /* include previous MAC */
    crypto_onetimeauth_update(&auth_state, mac, MAC_BYTES);
  crypto_onetimeauth_final(&auth_state, mac);

  /* compare MACs */
  return sodium_memcmp(mac, CHUNK_MAC(chunk->data), MAC_BYTES);
}

static int
check_chunk_type(struct chunk const * const chunk, const uint8_t chunk_type)
{
  if (chunk->data[CHUNK_TYPE_INDEX] == chunk_type) return 0;

  /* Tail truncation is the only case that might go undetected through MAC
   * verification above. So let's print a nice error message.
   *
   * Any other case is impossible, as the previous MAC verification would
   * have detected it
   */
  if ((chunk->data[CHUNK_TYPE_INDEX] == 0 ||
        chunk->data[CHUNK_TYPE_INDEX] == FIRST_CHUNK)
      && chunk_type == LAST_CHUNK) {

    fprintf(stderr, "Ciphertext's has been truncated.\n");
  }

  return -1;
}

static int
write_pt_chunk(struct chunk const * const chunk, FILE *output)
{
  if (fwrite(CHUNK_PT(chunk->data), CHUNK_PT_LEN(chunk->used), 1, output) < 1)
  {
    if (CHUNK_PT_LEN(chunk->used) == 0) return 0; /* special case: empty PT */
    perror("Couldn't write plaintext");
    return -1;
  }
  return 0;
}

static int
decrypt_next_chunk(
    struct chunk *chunk,
    uint8_t * const nonce,
    uint8_t const * const key,
    FILE *input,
    FILE *output)
{
  int8_t chunk_type; /* what it should be, from open_box's view */

  /* recycle chunk data */
  chunk->used = 0;

  /* read chunk */
  if (read_ct_chunk(chunk, input) == -1) return -1;

  /* verify MAC */
  if (verify_chunk(chunk, nonce, key) == -1) {
    fprintf(stderr, "Ciphertext couldn't be verified. It has been "
      "tampered with or you're using the wrong key.\n");
    return -1;
  }

  /* decrypt */
  crypto_stream_xsalsa20_xor_ic(CHUNK_CT(chunk->data), CHUNK_CT(chunk->data),
      CHUNK_CT_LEN(chunk->used), nonce, 1, key); /* 1 = initial counter */

  /* check chunk type */
  chunk_type = determine_ct_chunk_type(chunk, input);
  if (chunk_type == -1 || check_chunk_type(chunk, chunk_type) == -1)
    return -1;

  /* print plaintext */
  if (write_pt_chunk(chunk, output) == -1) return -1;

  /* increment nonce */
  sodium_increment(nonce, NONCE_BYTES);

  return 0;
}

void
open_box(FILE *input, FILE *output, uint8_t const * const key)
{
  uint8_t nonce[NONCE_BYTES];
  struct chunk *chunk = NULL;

  /* initialize chunk */
  if (chunk_malloc(&chunk) == -1) goto abort;

  /* read nonce */
  if (read_nonce(nonce, chunk->hex_buf, input) == -1) goto abort;

  /* decrypt first chunk */
  if (decrypt_next_chunk(chunk, nonce, key, input, output) == -1) goto abort;

  /* decrypt remaining chunks */
  chunk->is_first_chunk = false; /* not first chunk anymore */
  while (!feof(input)) {
    if (decrypt_next_chunk(chunk, nonce, key, input, output) == -1) goto abort;
  }

  /* cleanup */
  chunk_free(chunk);
  return;

abort: /* error */
  chunk_free(chunk);
  exit(EXIT_FAILURE);
}
// vim: et:ts=2:sw=2
