#include "lock_box.h"

void lock_box(FILE *input, FILE *output) {
  uint8_t nonce[NONCE_BYTES];
  struct chunk chunk;
  size_t nread;
  int8_t chunk_type; /* first, last or in between */
  _Bool is_first_chunk = true;
  unsigned char *subkey;
  unsigned char previous_mac[MAC_BYTES];
  crypto_onetimeauth_state auth_state;

  subkey = auth_subkey_malloc();

  if (isatty(fileno(output)))
    fprintf(stderr, "WARNING: Writing ciphertext to terminal.\n");

  /* new nonce */
  randombytes_buf(nonce, sizeof nonce);
  DEBUG_ONLY(hexDump("nonce", nonce, sizeof nonce));

  /* print nonce */
  if (fwrite(nonce, sizeof nonce, 1, output) < 1) {
    perror("Couldn't write ciphertext");
    goto abort;
  }

  init_chunk(&chunk);
  while(!feof(input)) {
    /* recycle chunk */
    chunk.used = MAC_BYTES + 1; /* reserve room for MAC + chunk_type */

    /* read complete chunk, if possible */
    nread = fread(&chunk.data[chunk.used], sizeof *chunk.data, CHUNK_PT_BYTES,
        input);
    chunk.used += nread;
    if (nread < CHUNK_PT_BYTES && ferror(input)) {
      fprintf(stderr, "Couldn't read plaintext.\n");
      goto abort;
    }
    DEBUG_ONLY(hexDump("read plaintext chunk",
          CHUNK_PT(chunk.data), CHUNK_PT_LEN(chunk.used)));

    chunk_type = determine_chunk_type(nread, CHUNK_PT_BYTES, is_first_chunk,
        input);
    if (chunk_type == -1) goto abort;

    /* set chunk type */
    chunk.data[CHUNK_TYPE_INDEX] = chunk_type;
    DEBUG_ONLY(hexDump("chunk type", &chunk.data[CHUNK_TYPE_INDEX], 1));

    /* encrypt chunk_type and plaintext (in-place) */
    crypto_stream_xsalsa20_xor_ic(CHUNK_CT(chunk.data), CHUNK_CT(chunk.data),
        CHUNK_CT_LEN(chunk.used), nonce, 1, key); /* 1 = initial counter */
    DEBUG_ONLY(hexDump("ciphertext chunk", CHUNK_CT(chunk.data),
          CHUNK_CT_LEN(chunk.used)));

    /* compute MAC */
    crypto_stream(subkey, sizeof subkey, nonce, key); /* new subkey */
    crypto_onetimeauth_init(&auth_state, subkey);
    crypto_onetimeauth_update(&auth_state, CHUNK_CT(chunk.data),
        CHUNK_CT_LEN(chunk.used));
    if (!is_first_chunk) {
      /* include previous MAC */
      crypto_onetimeauth_update(&auth_state, previous_mac, MAC_BYTES);
    }
    DEBUG_ONLY(hexDump("chunk MAC", CHUNK_MAC(chunk.data), MAC_BYTES));
    crypto_onetimeauth_final(&auth_state, CHUNK_MAC(chunk.data));
    memcpy(previous_mac, CHUNK_MAC(chunk.data), MAC_BYTES); /* remember MAC */

    /* print MAC + chunk_type + ciphertext */
    if (fwrite(chunk.data, chunk.used, 1, output) < 1) {
      perror("Couldn't write ciphertext");
      goto abort;
    }

    /* increment nonce */
    sodium_increment(nonce, sizeof nonce);

    /* not first chunk anymore */
    is_first_chunk = false;
  }
  sodium_free(subkey);
  free_chunk(&chunk);
  return;

abort:
  sodium_free(subkey);
  free_chunk(&chunk);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  arguments.key_source = RANDOM;
  argp_parse(&argp_parser, argc, argv, 0, 0, &arguments);

  if (sodium_init() == -1) {
    fprintf(stderr, "unable to initialize libsodium\n");
    exit(EXIT_FAILURE);
  }

  key = key_malloc();
  get_key(&arguments, key);

  FILE *input = open_input(&arguments);
  lock_box(input, stdout);
  close_input(input);

  return EXIT_SUCCESS;
}
// vim: et:ts=2:sw=2
