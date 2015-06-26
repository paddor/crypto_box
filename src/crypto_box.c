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

void grow_ct(ct_t *ct, size_t nbytes_coming) {
    // grow if needed
    while (ct->used + nbytes_coming > ct->size) {
      ct->size *= 2;
      ct->data = realloc(ct->data, ct->size * sizeof *ct->data);
      if (ct->data == NULL) {
        fprintf(stderr, "failed to grow ciphertext capacity to %zu bytes\n",
            ct->size);
        exit(EXIT_FAILURE);
      }
    }
}

void free_ct(ct_t *ct) {
  free(ct->data);
  ct->data = NULL;
  ct->used = ct->size = 0;
}


const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;
static char doc[] = "Easy to use, strong symmetric encryption on the command line.";
static char args_doc[] = "[KEY]";
static struct argp_option options[] = {
    // TODO: -f key_file
    { "ask", 'a', 0, 0, "Ask for the key"},
    { "hex", 'H', 0, 0, "read/write ciphertext as ASCII hex characters"},
    { 0 }
};

error_t parse_options(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;
  switch (key) {
  case 'a':
    arguments->key_source = ASK; break;
  case 'H':
    arguments->ct_format = HEX; break;
  case ARGP_KEY_ARG: // key on command line
    arguments->key_source = CMD;
    arguments->key = arg;
    break;
  default: return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

struct argp argp = { options, parse_options, args_doc, doc, 0, 0, 0 };

void get_key(const struct arguments * const arguments, uint8_t key[KEY_BYTES]) {
  switch (arguments->key_source) {
    case RANDOM:
      randombytes_buf(key, KEY_BYTES);
      char hex[KEY_BYTES * 2 + 1];
      sodium_bin2hex(hex, KEY_BYTES * 2 + 1, key, KEY_BYTES);
      fprintf(stderr, "%s\n", hex);
      break;
    case CMD:
      get_key_from_args(arguments->key, key);
      break;
    case ASK:
      fprintf(stderr, "asking for key\n");
      // TODO: ask for key
      exit(EXIT_FAILURE);
  }
  DEBUG_ONLY(hexDump("not so secret key", key, KEY_BYTES));
}

void get_key_from_args(const char *arg, uint8_t *key) {
  size_t bin_len, bytes_read;
  // TODO: warn about invalid characters
  if (-1 == sodium_hex2bin(key, KEY_BYTES, arg,
        strlen(arg), ":", &bin_len, NULL)) {
    fprintf(stderr, "Given key is too long, only %u bytes are useable!\n",
        KEY_BYTES);
    exit(EXIT_FAILURE);
  }
  if (bin_len < KEY_BYTES)
    fprintf(stderr, "WARNING: reuising key material to make up a key "
        "of sufficient length\n");
    bytes_read = bin_len;
    while (bytes_read < KEY_BYTES) {
      sodium_hex2bin(&key[bytes_read], KEY_BYTES - bytes_read,
        arg, strlen(arg), ": ", &bin_len, NULL);
      bytes_read += bin_len;
    }
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
// vim: et:ts=2:sw=2
