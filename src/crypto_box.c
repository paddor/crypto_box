#include "crypto_box.h"

void init_ct(ct_t *ct) {
  ct->data = malloc(INITIAL_CT_SIZE * sizeof *ct->data);
  if (ct->data == NULL) {
    fprintf(stderr, "ciphertext data couldn't be allocated\n");
    exit(EXIT_FAILURE);
  }
  ct->used = 0;
  ct->size = INITIAL_CT_SIZE;
}

void grow_ct(size_t nbytes_coming) {
    // grow if needed
    while (ct.used + nbytes_coming > ct.size) {
      ct.size *= 2;
      ct.data = realloc(ct.data, ct.size * sizeof *ct.data);
      if (ct.data == NULL) {
        fprintf(stderr, "failed to grow ciphertext capacity to %zu bytes\n",
            ct.size);
        exit(EXIT_FAILURE);
      }
    }
}

void free_ct(ct_t *ct) {
  free(ct->data);
  ct->data = NULL;
  ct->used = ct->size = 0;
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
      fprintf(stderr, "%s\n", hex);
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

void cleanup(void) {
  free_ct(&ct);
  sodium_munlock(key, sizeof key);
}

void hexDump (const char *desc, const void *addr, size_t len) {
    size_t i;
    uint8_t buff[17];
    uint8_t *pc = (uint8_t*)addr;

    // Output description if given.
    if (desc != NULL)
        fprintf (stderr, "%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                fprintf (stderr, "  %s\n", buff);

            // Output the offset.
            fprintf (stderr, "  %04zx ", i);
        }

        // Now the hex code for the specific character.
        fprintf (stderr, " %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        fprintf (stderr, "   ");
        i++;
    }

    // And print the final ASCII bit.
    fprintf (stderr, "  %s\n", buff);
}
