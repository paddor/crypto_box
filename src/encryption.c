#include "encryption.h"
#define NONCEBYTES crypto_stream_xsalsa20_NONCEBYTES
#define MACBYTES crypto_onetimeauth_BYTES

/* One variable in file scope so a simple call to cleanup() can be registered
 * with atexit().
 *
 * This simplifies error handling by allowing nested calls to call exit()/err()
 * too. */
static struct chunk *chunk;

static void
print_nonce(uint8_t const * const nonce, uint8_t *hex_buf, FILE *output)
{
  if (hex_buf == NULL) {
    if (fwrite(nonce, NONCEBYTES, 1, output) < 1)
      errx(EX_IOERR, "Couldn't write ciphertext");

  } else {
    char *hex_result; /* result of bin->hex conversion */
    hex_result = sodium_bin2hex((char *) hex_buf, 2 * NONCEBYTES + 1, nonce,
        NONCEBYTES);
    if (hex_result == NULL)
      errx(EX_SOFTWARE, "Couldn't convert nonce to hex.");

    if (fwrite(hex_buf, 2 * NONCEBYTES, 1, output) < 1)
      errx(EX_IOERR, "Couldn't write ciphertext");
  }
}

static void
read_pt_chunk(struct chunk * const chunk, FILE *input)
{
  size_t nread = fread(&chunk->data[chunk->used], 1,
      CHUNK_PT_BYTES, input);
  if (nread < CHUNK_PT_BYTES && ferror(input))
    errx(EX_IOERR, "Couldn't read plaintext.");

  chunk->used += nread;
}

static void
construct_chunk_mac(
    struct chunk const * const chunk,
    uint8_t const * const nonce,
    uint8_t const * const key)
{
  static unsigned char previous_mac[MACBYTES];
  crypto_onetimeauth_state auth_state;

  crypto_stream(chunk->subkey, crypto_onetimeauth_KEYBYTES, nonce, key);
  crypto_onetimeauth_init(&auth_state, chunk->subkey);
  crypto_onetimeauth_update(&auth_state, CHUNK_CT(chunk->data),
      CHUNK_CT_LEN(chunk->used));
  if (!chunk->is_first_chunk) {
    /* include previous MAC */
    crypto_onetimeauth_update(&auth_state, previous_mac, MACBYTES);
  }
  crypto_onetimeauth_final(&auth_state, CHUNK_MAC(chunk->data));

  /* remember MAC */
  memcpy(previous_mac, CHUNK_MAC(chunk->data), MACBYTES);
}

static void
print_ct_chunk(
  struct chunk const * const chunk,
  FILE *output)
{
  if (chunk->hex_buf == NULL) {
    if (fwrite(chunk->data, chunk->used, 1, output) < 1)
      errx(EX_IOERR, "Couldn't write ciphertext");

  } else {
    char *hex_result; /* result of bin->hex conversion */
    hex_result = sodium_bin2hex((char *) chunk->hex_buf, 2 * chunk->used + 1,
        chunk->data, chunk->used);
    if (hex_result == NULL)
      errx(EX_SOFTWARE, "Couldn't convert ciphertext to hex.");

    if (fwrite(chunk->hex_buf, chunk->used * 2, 1, output) < 1)
      errx(EX_IOERR, "Couldn't write ciphertext");
  }
}

static void
encrypt_next_chunk(
    struct chunk *chunk,
    uint8_t * const nonce,
    uint8_t const * const key,
    FILE *input,
    FILE *output)
{
  int8_t chunk_type; /* first, last or in between */

  /* recycle chunk data */
  chunk->used = MACBYTES + 1; /* reserve room for MAC + chunk_type */

  /* read complete chunk, if possible */
  read_pt_chunk(chunk, input);

  chunk_type = determine_pt_chunk_type(chunk, input);

  /* set chunk type */
  chunk->data[CHUNK_TYPE_INDEX] = chunk_type;

  /* encrypt chunk_type and plaintext (in-place) */
  crypto_stream_xsalsa20_xor_ic(CHUNK_CT(chunk->data), CHUNK_CT(chunk->data),
      CHUNK_CT_LEN(chunk->used), nonce, 1, key); /* 1 = initial counter */

  /* compute MAC */
  construct_chunk_mac(chunk, nonce, key);

  /* print MAC + chunk_type + ciphertext */
  print_ct_chunk(chunk, output);

  /* increment nonce */
  sodium_increment(nonce, NONCEBYTES);
}

static void cleanup(void)
{
  chunk_free(&chunk);
}

void
lock_box(FILE *input, FILE *output, uint8_t const * const key, bool hex)
{
  uint8_t nonce[NONCEBYTES];

  /* initialize chunk */
  chunk_malloc(&chunk, hex);
  atexit(cleanup);

  /* ciphertext to TTY warning */
  if (!hex && isatty(fileno(output)))
    warnx("Warning: Writing binary ciphertext to terminal.");

  /* new nonce */
  randombytes_buf(nonce, sizeof nonce);

  /* print nonce */
  print_nonce(nonce, chunk->hex_buf, output);

  /* encrypt first chunk */
  encrypt_next_chunk(chunk, nonce, key, input, output);

  /* encrypt remaining chunks */
  chunk->is_first_chunk = false; /* not first chunk anymore */
  while (!feof(input))
    encrypt_next_chunk(chunk, nonce, key, input, output);
}
// vim: et:ts=2:sw=2
