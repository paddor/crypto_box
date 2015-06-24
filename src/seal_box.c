#include "crypto_box.h"
#include "crypto_box.c"

void read_plaintext(void) {
  size_t nread;

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
  DEBUG_ONLY(hexDump("plain text", CT_AFTER_MAC(ct.data), PT_LEN(ct.used)));
}

// in-place encryption + MAC
void encrypt_then_mac(void) {
  crypto_secretbox_easy(ct.data, CT_AFTER_MAC(ct.data), PT_LEN(ct.used), nonce, key);
  DEBUG_ONLY(hexDump("MAC", ct.data, MAC_BYTES));
  DEBUG_ONLY(hexDump("cipher text", CT_AFTER_MAC(ct.data), PT_LEN(ct.used)));
}

void write_ciphertext() {
  fwrite(nonce, sizeof nonce, 1, stdout); // write nonce first
  fwrite(ct.data, sizeof *ct.data, ct.used, stdout); // then MAC and CT
  if (ferror(stdout)) {
    perror("Couldn't write cipher text: ");
    exit(EXIT_FAILURE);
  }
}

void get_nonce(void) {
  randombytes_buf(nonce, sizeof nonce);
  DEBUG_ONLY(hexDump("nonce", nonce, sizeof nonce));
}

int main(int argc, const char *argv[]) {
  parse_options(argc, argv);

  if (sodium_init() == -1) {
    fprintf(stderr, "unable to initialize libsodium\n");
    return 1;
  }

  sodium_mlock(key, sizeof key);
  atexit(cleanup);

  get_key(argv);
  get_nonce();

  init_ct(&ct);
  ct.used = MAC_BYTES; // reserve room for MAC

  read_plaintext();
  encrypt_then_mac();
  write_ciphertext();

  return EXIT_SUCCESS;
}
// vim: et:ts=2:sw=2
