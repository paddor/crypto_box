#include "crypto_box.h"

void lock_box(FILE *input, FILE *output) {
  size_t nread;
  unsigned char *subkey;
  unsigned char mac_mac[crypto_onetimeauth_BYTES];
  crypto_onetimeauth_state mac_mac_state;

  /* initialize state for MAC of MACs */
  subkey = sodium_malloc(crypto_onetimeauth_KEYBYTES);
  if (subkey == NULL) {
    fprintf(stderr, "Memory for authentication subkey couldn't be "
        "allocated.\n");
    exit(EXIT_FAILURE);
  }
  randombytes_buf(nonce, sizeof nonce);
  crypto_stream(subkey, sizeof subkey, nonce, key);
  crypto_onetimeauth_init(&mac_mac_state, subkey);

  if (isatty(fileno(output)))
    fprintf(stderr, "WARNING: Writing ciphertext to terminal.\n");

  /* print nonce for subkey */
  if (fwrite(nonce, sizeof nonce, 1, output) < 1) {

    perror("Couldn't write ciphertext");
    exit(EXIT_FAILURE);
  }

  init_ct(&ct);
  while(!feof(input)) {
    /* recycle ct */
    ct.used = MAC_BYTES; /* reserve room for MAC */

    /* read complete chunk, if possible */
    grow_ct(&ct, CHUNK_BYTES);
    nread = fread(&ct.data[ct.used], sizeof *ct.data, CHUNK_BYTES, input);
    ct.used += nread;
    DEBUG_ONLY(hexDump("read plaintext chunk",
          CT_AFTER_MAC(ct.data), PT_LEN(ct.used)));

    if (nread < CHUNK_BYTES && ferror(input)) {
      fprintf(stderr, "Couldn't read plaintext.\n");
      exit(EXIT_FAILURE);
    }

    /* new nonce */
    randombytes_buf(nonce, sizeof nonce);
    DEBUG_ONLY(hexDump("nonce", nonce, sizeof nonce));

    /* encrypt chunk */
    crypto_secretbox_easy(ct.data, CT_AFTER_MAC(ct.data), PT_LEN(ct.used),
        nonce, key);
    DEBUG_ONLY(hexDump("chunk MAC", ct.data, MAC_BYTES));
    DEBUG_ONLY(hexDump("ciphertext chunk", CT_AFTER_MAC(ct.data),
          PT_LEN(ct.used)));

    /* print ciphertext */
    if (fwrite(nonce, sizeof nonce, 1, output) < 1 || /* nonce */
        fwrite(ct.data, ct.used, 1, output) < 1) { /* MAC and CT */

      perror("Couldn't write ciphertext");
      exit(EXIT_FAILURE);
    }

    /* update mac_mac_state */
    crypto_onetimeauth_update(&mac_mac_state, ct.data,
        crypto_onetimeauth_BYTES);
  }
  free_ct(&ct);

  /* print mac_mac */
  crypto_onetimeauth_final(&mac_mac_state, mac_mac);
  DEBUG_ONLY(hexDump("MAC of MACs", mac_mac, crypto_onetimeauth_BYTES));
  if (fwrite(mac_mac, sizeof mac_mac, 1, output) < 1) {
    perror("Couldn't write ciphertext");
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char *argv[]) {
  arguments.key_source = RANDOM;
  argp_parse(&argp_parser, argc, argv, 0, 0, &arguments);

  if (sodium_init() == -1) {
    fprintf(stderr, "unable to initialize libsodium\n");
    exit(EXIT_FAILURE);
  }

  key_mlock();
  get_key(&arguments, key);

  FILE *input = open_input(&arguments);
  lock_box(input, stdout);
  close_input(input);

  return EXIT_SUCCESS;
}
// vim: et:ts=2:sw=2
