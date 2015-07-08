#include "open_box.h"

void open_box(FILE *input, FILE *output) {
  uint8_t nonce[NONCE_BYTES];
  struct chunk chunk;
  size_t nread;
  int8_t chunk_type; /* what it should be, from open_box's view */
  _Bool is_first_chunk = true;
  unsigned char *subkey;
  unsigned char mac_should[MAC_BYTES];
  unsigned char previous_mac[MAC_BYTES];
  crypto_onetimeauth_state auth_state;

  subkey = auth_subkey_malloc();

  /* read nonce for authentication subkey */
  if (fread(&nonce, sizeof nonce, 1, input) < 1) {
    fprintf(stderr, "Couldn't read ciphertext.\n");
    exit(EXIT_FAILURE);
  }

  init_chunk(&chunk);
  while(!feof(input)) {
    /* recycle chunk */
    chunk.used = 0;

    /* read complete chunk, if possible */
    nread = fread(&chunk.data[chunk.used], sizeof *chunk.data, CHUNK_CT_BYTES,
        input);
    chunk.used += nread;
    DEBUG_ONLY(hexDump("ciphertext chunk read", chunk.data, chunk.used));

    /* truncated header */
    if (nread <= 17) { /* MAC + chunk_type = 17 */
      fprintf(stderr, "Ciphertext's has been truncated.\n");
      goto abort;
    }

    if (nread < (CHUNK_CT_BYTES) && ferror(input)) {
      fprintf(stderr, "Couldn't read ciphertext.\n");
      goto abort;
    }

    chunk_type = determine_chunk_type(nread, CHUNK_CT_BYTES, is_first_chunk,
        input);
    if (chunk_type == -1) goto abort;

    /* compute MAC */
    crypto_stream(subkey, sizeof subkey, nonce, key); /* new subkey */
    crypto_onetimeauth_init(&auth_state, subkey);
    crypto_onetimeauth_update(&auth_state, CHUNK_CT(chunk.data),
        CHUNK_CT_LEN(chunk.used));
    if (!is_first_chunk) {
      /* include previous MAC */
      crypto_onetimeauth_update(&auth_state, previous_mac, MAC_BYTES);
    }
    DEBUG_ONLY(hexDump("calculated chunk MAC", CHUNK_MAC(chunk.data),
          MAC_BYTES));
    crypto_onetimeauth_final(&auth_state, mac_should);
    memcpy(previous_mac, mac_should, MAC_BYTES); /* remember MAC */

    /* verify MAC */
    if (sodium_memcmp(mac_should, CHUNK_MAC(chunk.data), MAC_BYTES) != 0) {
      fprintf(stderr, "Ciphertext couldn't be verified. It has been "
        "tampered with or you're using the wrong key.\n");
      goto abort;
    }

    /* decrypt */
    crypto_stream_xsalsa20_xor_ic(CHUNK_CT(chunk.data), CHUNK_CT(chunk.data),
        CHUNK_CT_LEN(chunk.used), nonce, 1, key); /* 1 = initial counter */
    DEBUG_ONLY(hexDump("plain text", CHUNK_PT(chunk.data),
        CHUNK_PT_LEN(chunk.used)));

    /* check chunk type */
    if (chunk.data[CHUNK_TYPE_INDEX] != chunk_type) {
      /* Tail truncation, is the only case that might go undetected through MAC
       * verification above. So let's print a nice error message.
       *
       * Any other case is impossible, as the previous MAC verification would
       * have detected it
       */
      if ((chunk.data[CHUNK_TYPE_INDEX] == 0 ||
            chunk.data[CHUNK_TYPE_INDEX] == FIRST_CHUNK)
          && chunk_type == LAST_CHUNK) {
        fprintf(stderr, "Ciphertext's has been truncated.\n");
      }

      goto abort;
    }

    /* print plaintext */
    if (fwrite(CHUNK_PT(chunk.data), CHUNK_PT_LEN(chunk.used), 1, output) < 1)
    {
      perror("Couldn't write plaintext");
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
  arguments.key_source = CMD;
  argp_parse(&argp_parser, argc, argv, 0, 0, &arguments);
  if (arguments.key_source == RANDOM) {
    fprintf(stderr, "Key can't be random while opening a box");
    exit(EXIT_FAILURE);
  }

  if (sodium_init() == -1) {
    fprintf(stderr, "unable to initialize libsodium\n");
    exit(EXIT_FAILURE);
  }

  key = key_malloc();
  get_key(&arguments, key);

  FILE *input = open_input(&arguments);
  open_box(input, stdout);
  close_input(input);

  return EXIT_SUCCESS;
}
// vim: et:ts=2:sw=2
