#include "crypto_box.h"
#include "crypto_box.c"

void read_ciphertext(void) {
  size_t nread;

  // read nonce
  while(!fread(&nonce, sizeof nonce, 1, stdin))
    ;
  DEBUG_ONLY(hexDump("nonce", nonce, sizeof nonce));

  while(1) {

    grow_ct(READ_BYTES);

    nread = fread(&ct.data[ct.used], sizeof *ct.data, READ_BYTES, stdin);
    ct.used += nread;

    if (READ_BYTES == nread) continue;
    if (feof(stdin)) break;
    if (ferror(stdin)) {
      fprintf(stderr, "unable to read from STDIN:");
      exit(EXIT_FAILURE);
    }
  }
  DEBUG_ONLY(hexDump("cipher text", ct.data, ct.used));
}

// verify MAC and in-place decryption
void verify_then_decrypt(void) {
  if(-1 == crypto_secretbox_open_easy(CT_AFTER_MAC(ct.data), ct.data, ct.used, nonce, key)) {
    fprintf(stderr, "Ciphertext couldn't be verified. It has been "
      "tampered with or you're using the wrong key.\n");
    exit(EXIT_FAILURE);
  }
  DEBUG_ONLY(hexDump("plain text", CT_AFTER_MAC(ct.data), PT_LEN(ct.used)));
}

void write_plaintext() {
  fwrite(CT_AFTER_MAC(ct.data), sizeof *ct.data, PT_LEN(ct.used), stdout);
  if (ferror(stdout)) {
    perror("Couldn't write plain text: ");
    exit(EXIT_FAILURE);
  }
}

int main(int argc, const char *argv[]) {
  parse_options(argc, argv);
  if (key_source == RANDOM) {
          fprintf(stderr, "Key can't be random while opening a box");
          exit(EXIT_FAILURE);
  }

  if (sodium_init() == -1) {
    fprintf(stderr, "unable to initialize libsodium\n");
    return 1;
  }

  sodium_mlock(key, sizeof key);
  atexit(cleanup);

  get_key(argv);

  init_ct(&ct);

  read_ciphertext();
  verify_then_decrypt();
  write_plaintext();

  return EXIT_SUCCESS;
}
// vim: et:ts=2:sw=2
