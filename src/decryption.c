#include "decryption.h"
#define NONCEBYTES crypto_stream_xsalsa20_NONCEBYTES
#define MACBYTES crypto_onetimeauth_BYTES

/* One variable in file scope so a simple call to cleanup() can be registered
 * with atexit().
 *
 * This simplifies error handling by allowing nested calls to call exit()/err()
 * too. */
static struct chunk *chunk;

static void
read_nonce(uint8_t * const nonce, uint8_t *hex_buf, FILE *input)
{
  size_t bin_len; /* length of binary data written during conversion  */
  int hex_result; /* result of hex->bin conversion */
  if (hex_buf == NULL) {
    if (fread(nonce, NONCEBYTES, 1, input) < 1)
      errx(EX_IOERR, "Couldn't read ciphertext.");

  } else {
    if (fread(hex_buf, NONCEBYTES * 2, 1, input) < 1)
      errx(EX_IOERR, "Couldn't read ciphertext.");

    hex_result = sodium_hex2bin(nonce, NONCEBYTES, (const char*) hex_buf,
        NONCEBYTES * 2, NULL, &bin_len, NULL);
    if (hex_result != 0 || bin_len < NONCEBYTES)
      errx(EX_SOFTWARE, "Couldn't convert to binary ciphertext.");
  }
}

static void
read_ct_chunk(struct chunk * const chunk, FILE *input)
{
  if (chunk->hex_buf == NULL) {
    chunk->used = fread(chunk->data, 1, chunk->size, input);
  } else {
    size_t nread = fread(chunk->hex_buf, 2, CHUNK_CT_BYTES, input);
    if (nread < CHUNK_CT_BYTES && ferror(input))
      errx(EX_IOERR, "Couldn't read ciphertext.");

    int hex_result; /* result of hex->bin conversion */
    hex_result = sodium_hex2bin(chunk->data, chunk->size,
        (const char*) chunk->hex_buf, nread * 2, NULL, &chunk->used, NULL);
    if (hex_result != 0 || chunk->used < nread)
      errx(EX_SOFTWARE, "Couldn't convert to binary ciphertext.");
  }

  /* truncated header */
  if (chunk->used < 17) /* MAC + chunk_type = 17 */
    errx(EX_DATAERR, "Ciphertext's header has been truncated.");

  /* read error */
  if (chunk->used < (CHUNK_CT_BYTES) && ferror(input))
    errx(EX_IOERR, "Couldn't read ciphertext.");
}

static void
verify_chunk(
    struct chunk const * const chunk,
    uint8_t const * const nonce,
    uint8_t const * const key)
{
  static unsigned char mac[MACBYTES];
  crypto_onetimeauth_state auth_state;

  /* derive subkey */
  crypto_stream(chunk->subkey, crypto_onetimeauth_KEYBYTES, nonce, key);

  /* compute MAC */
  crypto_onetimeauth_init(&auth_state, chunk->subkey);
  crypto_onetimeauth_update(&auth_state, CHUNK_CT(chunk->data),
      CHUNK_CT_LEN(chunk->used));
  if (!chunk->is_first_chunk) /* include previous MAC */
    crypto_onetimeauth_update(&auth_state, mac, MACBYTES);
  crypto_onetimeauth_final(&auth_state, mac);

  /* compare MACs */
  if (sodium_memcmp(mac, CHUNK_MAC(chunk->data), MACBYTES) == 0) return;

  errx(EX_DATAERR, "Ciphertext couldn't be verified. It has been "
    "tampered with or you're using the wrong key.");
}

static void
check_chunk_type(struct chunk const * const chunk, const uint8_t chunk_type)
{
  if (chunk->data[CHUNK_TYPE_INDEX] == chunk_type) return;

  /* Tail truncation is the only case that might go undetected through MAC
   * verification above. So let's print a nice error message.
   *
   * Any other case is impossible, as the previous MAC verification would
   * have detected it
   */
  if ((chunk->data[CHUNK_TYPE_INDEX] == 0 ||
        chunk->data[CHUNK_TYPE_INDEX] == CHUNK_TYPE_FIRST)
      && chunk_type == CHUNK_TYPE_LAST) {

    errx(EX_DATAERR, "Ciphertext's has been truncated.");
  }
}

static void
write_pt_chunk(struct chunk const * const chunk, FILE *output)
{
  if (fwrite(CHUNK_PT(chunk->data), CHUNK_PT_LEN(chunk->used), 1, output) == 1)
    return;

  if (CHUNK_PT_LEN(chunk->used) == 0) return; /* special case: empty PT */

  errx(EX_IOERR, "Couldn't write plaintext");
}

static void
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
  read_ct_chunk(chunk, input);

  /* verify MAC */
  verify_chunk(chunk, nonce, key);

  /* decrypt */
  crypto_stream_xsalsa20_xor_ic(CHUNK_CT(chunk->data), CHUNK_CT(chunk->data),
      CHUNK_CT_LEN(chunk->used), nonce, 1, key); /* 1 = initial counter */

  /* check chunk type */
  chunk_type = determine_ct_chunk_type(chunk, input);
  check_chunk_type(chunk, chunk_type);

  /* print plaintext */
  write_pt_chunk(chunk, output);

  /* increment nonce */
  sodium_increment(nonce, NONCEBYTES);
}

static void cleanup(void)
{
  chunk_free(chunk);
}

void
open_box(FILE *input, FILE *output, uint8_t const * const key, bool hex)
{
  uint8_t nonce[NONCEBYTES];

  /* initialize chunk */
  chunk_malloc(&chunk, hex);
  atexit(cleanup);

  /* read nonce */
  read_nonce(nonce, chunk->hex_buf, input);

  /* decrypt first chunk */
  decrypt_next_chunk(chunk, nonce, key, input, output);

  /* decrypt remaining chunks */
  chunk->is_first_chunk = false; /* not first chunk anymore */
  while (!feof(input))
    decrypt_next_chunk(chunk, nonce, key, input, output);
}
// vim: et:ts=2:sw=2
