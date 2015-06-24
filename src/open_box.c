#include "crypto_box.h"

static uint8_t key[KEY_BYTES];
static uint8_t nonce[NONCE_BYTES];
static ct_format_t ct_format = BIN;
static key_source_t key_source = CMD;
static ct_t ct;

void read_ciphertext(FILE *input) {
  size_t nread;

  // read nonce
  while(!fread(&nonce, sizeof nonce, 1, input))
    ;
  DEBUG_ONLY(hexDump("nonce", nonce, sizeof nonce));

  while(1) {

    grow_ct(&ct, READ_BYTES);

    nread = fread(&ct.data[ct.used], sizeof *ct.data, READ_BYTES, input);
    ct.used += nread;

    if (READ_BYTES == nread) continue;
    if (feof(input)) break;
    if (ferror(input)) {
      perror("Couldn't read ciphertext");
      exit(EXIT_FAILURE);
    }
  }
  DEBUG_ONLY(hexDump("ciphertext", ct.data, ct.used));
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

void write_plaintext(FILE *output) {
  fwrite(CT_AFTER_MAC(ct.data), sizeof *ct.data, PT_LEN(ct.used), output);
  if (ferror(output)) {
    perror("Couldn't write plaintext");
    exit(EXIT_FAILURE);
  }
}

int main(int argc, const char *argv[]) {
  parse_options(&key_source, &ct_format, argc, argv);
  if (key_source == RANDOM) {
    fprintf(stderr, "Key can't be random while opening a box");
    exit(EXIT_FAILURE);
  }

  if (sodium_init() == -1) {
    fprintf(stderr, "unable to initialize libsodium\n");
    exit(EXIT_FAILURE);
  }

  sodium_mlock(key, sizeof key);
  get_key(key_source, key, argv);

  init_ct(&ct);

  read_ciphertext(stdin);
  verify_then_decrypt();
  write_plaintext(stdout);
  free_ct(&ct);

  return EXIT_SUCCESS;
}
// vim: et:ts=2:sw=2
