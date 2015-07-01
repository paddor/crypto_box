#include "crypto_box.h"

void open_box(FILE *input, FILE *output) {
  size_t nread;
  unsigned char *subkey;
  unsigned char mac_mac[crypto_onetimeauth_BYTES];
  unsigned char *input_mac_mac;
  crypto_onetimeauth_state mac_mac_state;
  crypto_onetimeauth_init(&mac_mac_state, key);

  /* read nonce for authentication subkey */
  if (fread(&nonce, sizeof nonce, 1, input) < 1) {
    fprintf(stderr, "Couldn't read ciphertext.\n");
    exit(EXIT_FAILURE);
  }

  /* initialize state for MAC of MACs */
  subkey = sodium_malloc(crypto_onetimeauth_KEYBYTES);
  if (subkey == NULL) {
    fprintf(stderr, "Memory for authentication subkey couldn't be "
        "allocated.\n");
    exit(EXIT_FAILURE);
  }
  crypto_stream(subkey, sizeof subkey, nonce, key);
  crypto_onetimeauth_init(&mac_mac_state, subkey);

  init_ct(&ct);
  while(!feof(input)) {
    /* recycle ct */
    ct.used = 0;

    /* read nonce */
    if (fread(&nonce, sizeof nonce, 1, input) < 1) {
      fprintf(stderr, "Couldn't read ciphertext.\n");
      exit(EXIT_FAILURE);
    }

    /* read complete chunk, if possible */
    grow_ct(&ct, MAC_BYTES+CHUNK_BYTES);
    nread = fread(&ct.data[ct.used], sizeof *ct.data, MAC_BYTES+CHUNK_BYTES, input);
    ct.used += nread;
    DEBUG_ONLY(hexDump("read ciphertext chunk", ct.data, ct.used));

    if (nread < (MAC_BYTES+CHUNK_BYTES)) {
      if (ferror(input)) {
        fprintf(stderr, "Couldn't read ciphertext.\n");
        exit(EXIT_FAILURE);
      }

      /* This is the very last chunk. The last bytes are MAC of MACs.
       */
      ct.used -= MAC_BYTES;
      input_mac_mac = &ct.data[ct.used];
    } else {
      /* Looks like a complete chunk, but we might be right before EOF, so
       * check for that */
      int c;
      if ((c = getc(input)) == EOF) {
        if (feof(input)) {
          /* We're right before EOF, how unfortunate!
           * What looked like a complete chunk is actually the last (short)
           * chunk with the MAC of MACs appended.
           */
          ct.used -= MAC_BYTES;
          input_mac_mac = &ct.data[ct.used];
        }
      } else {
        /* So this actually is a complete chunk. No trailing MAC. Let's put the
         * character back. */
        if (ungetc(c, input) == EOF) {
          fprintf(stderr, "Couldn't put character back to ciphertext.\n");
          exit(EXIT_FAILURE);
        }
      }
    }

    /* update mac_mac_state */
    crypto_onetimeauth_update(&mac_mac_state, ct.data,
        crypto_onetimeauth_BYTES);

    /* decrypt */
    if(-1 == crypto_secretbox_open_easy(CT_AFTER_MAC(ct.data), ct.data,
          ct.used, nonce, key)) {
      fprintf(stderr, "Ciphertext couldn't be verified. It has been "
        "tampered with or you're using the wrong key.\n");
      exit(EXIT_FAILURE);
    }
    DEBUG_ONLY(hexDump("plain text", CT_AFTER_MAC(ct.data), PT_LEN(ct.used)));

    /* print plaintext */
    if (fwrite(CT_AFTER_MAC(ct.data), PT_LEN(ct.used), 1, output) < 1) {
      perror("Couldn't write plaintext");
      exit(EXIT_FAILURE);
    }
  }
  free_ct(&ct);

  /* verify mac_mac */
  crypto_onetimeauth_final(&mac_mac_state, mac_mac);
  DEBUG_ONLY(hexDump("calculated MAC of MACs", mac_mac,
        crypto_onetimeauth_BYTES));
  if (sodium_memcmp(mac_mac, input_mac_mac, crypto_onetimeauth_BYTES) != 0) {
    fprintf(stderr, "Previous MACs couldn't be verified. Your locked box has "
        "been tampered with!\n");
    exit(EXIT_FAILURE);
  }
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

  key_mlock();
  get_key(&arguments, key);

  FILE *input = open_input(&arguments);
  open_box(input, stdout);
  close_input(input);

  return EXIT_SUCCESS;
}
// vim: et:ts=2:sw=2
