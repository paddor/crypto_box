#include "crypto_box.h"

void read_plaintext(FILE *input) {
  size_t nread;

  while(1) {
    grow_ct(&ct, READ_BYTES);

    nread = fread(&ct.data[ct.used], sizeof *ct.data, READ_BYTES, input);
    ct.used += nread;

    if (READ_BYTES == nread) continue;
    if (feof(input)) break;
    if (ferror(input)) {
      perror("Couldn't read plaintext");
      exit(EXIT_FAILURE);
    }
  }
  DEBUG_ONLY(hexDump("plaintext", CT_AFTER_MAC(ct.data), PT_LEN(ct.used)));
}

// in-place encryption + MAC
void encrypt_then_mac(void) {
  crypto_secretbox_easy(ct.data, CT_AFTER_MAC(ct.data), PT_LEN(ct.used), nonce, key);
  DEBUG_ONLY(hexDump("MAC", ct.data, MAC_BYTES));
  DEBUG_ONLY(hexDump("ciphertext", CT_AFTER_MAC(ct.data), PT_LEN(ct.used)));
}

void write_ciphertext(FILE *output) {
  if (isatty(fileno(output))) {
    fprintf(stderr, "WARNING: Writing ciphertext to terminal.\n");
  }

  fwrite(nonce, sizeof nonce, 1, output); // write nonce first
  fwrite(ct.data, sizeof *ct.data, ct.used, output); // then MAC and CT
  if (ferror(output)) {
    perror("Couldn't write ciphertext");
    exit(EXIT_FAILURE);
  }
}

void get_nonce(void) {
  randombytes_buf(nonce, sizeof nonce);
  DEBUG_ONLY(hexDump("nonce", nonce, sizeof nonce));
}

int main(int argc, char *argv[]) {
  struct arguments arguments;
  arguments.input_source = STDIN;
  arguments.ct_format = BIN;
  arguments.key_source = RANDOM;
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  if (sodium_init() == -1) {
    fprintf(stderr, "unable to initialize libsodium\n");
    exit(EXIT_FAILURE);
  }

  key_mlock();
  get_key(&arguments, key);
  get_nonce();

  init_ct(&ct);
  ct.used = MAC_BYTES; // reserve room for MAC

  FILE *input = open_input(&arguments);
  read_plaintext(input);
  close_input(input);
  encrypt_then_mac();
  write_ciphertext(stdout);
  free_ct(&ct);

  return EXIT_SUCCESS;
}
// vim: et:ts=2:sw=2
