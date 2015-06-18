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
  hexDump("plain text", CT_AFTER_MAC(ct.data), ct.used - MAC_BYTES);
}

// in-place encryption + MAC
void encrypt_then_mac(void) {
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

void parse_options(int argc, const char *argv[]) {
  int opt;
  while ((opt = getopt(argc, (char * const *)argv, "aH")) != -1) {
      switch (opt) {
      case 'a':
        fprintf(stderr, "option -a recognized\n");
        key_source = ASK;
        break;
      case 'H':
        fprintf(stderr, "option -H recognized\n");
        ciphertext = HEX;
        break;
      default:
          fprintf(stderr, "Usage: %s [-aH] [hex-key]\n", argv[0]);
          exit(EXIT_FAILURE);
      }
  }
  if (optind >= argc) {
    fprintf(stderr, "no key on command line given\n");
  } else {
    fprintf(stderr, "key on command line given\n");
    key_source = CMD;
  }
}

void get_key(const char * argv[]) {
  switch (key_source) {
    case RANDOM:
      fprintf(stderr, "using random key\n");
      randombytes_buf(key, sizeof key);
      char hex[sizeof key * 2 + 1];
      sodium_bin2hex(hex, sizeof key * 2 + 1, key, sizeof key);
      fprintf(stderr, "Your key: %s\n", hex);
      break;
    case CMD:
      fprintf(stderr, "using key from command line\n");
      size_t bin_len;
      if (-1 == sodium_hex2bin(key, sizeof key, argv[optind],
            strlen(argv[optind]), ": ", &bin_len, NULL)) {
        fprintf(stderr, "Given key is too long, only %lu bytes are useable!\n",
            sizeof key);
        exit(EXIT_FAILURE);
      }
      if (bin_len < sizeof key)
        fprintf(stderr, "WARNING: reuising key material to make up a key "
            "of sufficient length\n");
        size_t bytes_read = bin_len;
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
  hexDump("not so secret key", key, sizeof key);
}

void get_nonce(void) {
  randombytes_buf(nonce, sizeof nonce);
  hexDump("nonce", nonce, sizeof nonce);
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

  read_plaintext();
  encrypt_then_mac();
  write_ciphertext();

  return EXIT_SUCCESS;
}
// vim: et:ts=2:sw=2
