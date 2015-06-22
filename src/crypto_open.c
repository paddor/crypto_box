#include "crypto_box.h"

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

void cleanup(void) {
  free_ct(&ct);
  sodium_munlock(key, sizeof key);
}

void parse_options(int argc, const char *argv[]) {
  // TODO: -f key_file
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
    exit(EXIT_FAILURE); // TODO: remove when asking is implemented
  } else {
    key_source = CMD;
  }
}

void get_key(const char * argv[]) {
  size_t bin_len, bytes_read;
  switch (key_source) {
    case RANDOM:
      // should never be random
      exit(EXIT_FAILURE);
      break;
    case CMD:
      if (-1 == sodium_hex2bin(key, sizeof key, argv[optind],
            strlen(argv[optind]), ": ", &bin_len, NULL)) {
        fprintf(stderr, "Given key is too long, only %lu bytes are useable!\n",
            sizeof key);
        exit(EXIT_FAILURE);
      }
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

int main(int argc, const char *argv[]) {
  parse_options(argc, argv);

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