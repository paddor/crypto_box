#include "crypto_box.h"

#define READ_BYTES 128

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
  hexDump("plain text", CT_AFTER_MAC(ct.data), ct.used - MAC_BYTES);
}

// in-place encryption + MAC
void encrypt(void) {
  crypto_secretbox_easy(ct.data, CT_AFTER_MAC(ct.data), ct.used, nonce, key);
  hexDump("MAC", ct.data, MAC_BYTES);
  hexDump("cipher text", CT_AFTER_MAC(ct.data), ct.used - MAC_BYTES);
}

void write_ciphertext() {
  fwrite(ct.data, sizeof *ct.data, ct.used, stdout);
  if (ferror(stdout)) {
    perror("Couldn't write cipher text: ");
    exit(EXIT_FAILURE);
  }
}

void cleanup(void) {
  free_ct(&ct);
  sodium_munlock(key, sizeof key);
}

int main(int argc, const char *argv[]) {
  if (sodium_init() == -1) {
    fprintf(stderr, "unable to initialize libsodium\n");
    return 1;
  }

  sodium_mlock(key, sizeof key);
  atexit(cleanup);
  randombytes_buf(key, sizeof key);
  hexDump("not so secret key", key, crypto_secretbox_KEYBYTES);
  randombytes_buf(nonce, sizeof nonce);
  hexDump("nonce", nonce, crypto_secretbox_NONCEBYTES);

  init_ct(&ct);

  read_plaintext();
  encrypt();
  write_ciphertext();

  return EXIT_SUCCESS;
}
// vim: et:ts=2:sw=2
