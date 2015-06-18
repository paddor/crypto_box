#include "crypto_box.h"

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

void cleanup(void) {
  free_ct(&ct);
  sodium_munlock(key, sizeof key);
}

void parse_options(int argc, const char *argv[]) {
  int opt;
  while ((opt = getopt(argc, (char * const *)argv, "aH")) != -1) {
      switch (opt) {
      case 'a':
        key_source = ASK;
        break;
      case 'H':
        ciphertext = HEX;
        break;
      default:
          fprintf(stderr, "Usage: %s [-aH] [hex-key]\n", argv[0]);
          exit(EXIT_FAILURE);
      }
  }
  if (optind >= argc) {
    // no key on command line given
  } else {
    key_source = CMD;
  }
}

void get_key(const char * argv[]) {
  size_t bin_len, bytes_read;
  switch (key_source) {
    case RANDOM:
      randombytes_buf(key, sizeof key);
      char hex[sizeof key * 2 + 1];
      sodium_bin2hex(hex, sizeof key * 2 + 1, key, sizeof key);
      fprintf(stderr, "Your key: %s\n", hex);
      break;
    case CMD:
      // TODO: warn about invalid characters
      if (-1 == sodium_hex2bin(key, sizeof key, argv[optind],
            strlen(argv[optind]), ":", &bin_len, NULL)) {
        fprintf(stderr, "Given key is too long, only %lu bytes are useable!\n",
            sizeof key);
        exit(EXIT_FAILURE);
      }
      if (bin_len < sizeof key)
        fprintf(stderr, "WARNING: reuising key material to make up a key "
            "of sufficient length\n");
        bytes_read = bin_len;
        while (bytes_read < sizeof key) {
          sodium_hex2bin(&key[bytes_read], sizeof key - bytes_read,
            argv[optind], strlen(argv[optind]), ": ", &bin_len, NULL);
          bytes_read += bin_len;
        }
      break;
    case ASK:
      fprintf(stderr, "asking for key\n");
      // TODO: ask for key
      exit(EXIT_FAILURE);
  }
  DEBUG_ONLY(hexDump("not so secret key", key, sizeof key));
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
