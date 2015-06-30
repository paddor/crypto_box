#include "crypto_box.h"

void init_ct(struct ciphertext *ct) {
  ct->data = malloc(INITIAL_CT_SIZE * sizeof *ct->data);
  if (ct->data == NULL) {
    fprintf(stderr, "ciphertext data couldn't be allocated\n");
    exit(EXIT_FAILURE);
  }
  ct->used = 0;
  ct->size = INITIAL_CT_SIZE;
}

void grow_ct(struct ciphertext *ct, size_t nbytes_coming) {
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

void free_ct(struct ciphertext *ct) {
  free(ct->data);
  ct->data = NULL;
  ct->used = ct->size = 0;
}


const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;
static char doc[] = "Easy to use, strong symmetric encryption on the command line.";
static char args_doc[] = "[KEY]";
static struct argp_option options[] = {
    { "key-file", 'k', "FILE", 0, "get key from file"},
    { "ask", 'a', 0, 0, "Ask for the key (requires -f)"},
    { "file", 'f', "FILE", 0, "get data from file instead of STDIN"},
    { "hex", 'H', 0, 0, "read/write ciphertext as ASCII hex characters"},
    { 0 }
};

error_t parse_options(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;
  switch (key) {
  case 'k':
    arguments->key_source = KEY_FILE;
    arguments->key_file = arg;
    break;
  case 'a':
    arguments->key_source = ASK; break;
  case 'f':
    arguments->input_source = INPUT_FILE;
    arguments->input_file = arg;
    break;
  case 'H':
    arguments->ct_format = HEX; break;
  case ARGP_KEY_ARG: // key on command line
    arguments->key_source = CMD;
    arguments->key = arg;
    break;
  case ARGP_KEY_SUCCESS: // finished parsing of args
    /* sanity check */
    if (arguments->key_source == ASK && arguments->input_source == STDIN) {
      fprintf(stderr, "Can't use -a without -f.\n");
      exit(EXIT_FAILURE);
    }
  default: return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

struct argp argp = { options, parse_options, args_doc, doc, 0, 0, 0 };

void get_key_from_file(const char *key_file, uint8_t *key) {
  FILE *f = fopen(key_file, "r");
  if(f == NULL && errno != ENOENT) {
    perror("Couldn't open key file");
    exit(EXIT_FAILURE);
  }
  if (f == NULL && errno == ENOENT) { // we'll create the file
    int fd = open(key_file, O_WRONLY | O_CREAT | O_EXCL, 0400);
    if (fd == -1) {
      perror("Couldn't create key file");
      exit(EXIT_FAILURE);
    }
    f = fdopen(fd, "w");
    if (f == NULL) {
      perror("Couldn't associate stream with file descriptor");
      exit(EXIT_FAILURE);
    }
    randombytes_buf(key, KEY_BYTES); // generate random key
    if (fwrite(key, KEY_BYTES, 1, f) == 0) { // write to file
      perror("Couldn't write key file");
      exit(EXIT_FAILURE);
    }
  } else {
    struct stat s;
    if (fstat(fileno(f), &s) != 0) {
      perror("Couldn't stat key file");
      exit(EXIT_FAILURE);
    }

    // check file permissions
    if ((s.st_mode & 077) > 0) {
      fprintf(stderr, "Key file is readable by other users! Please specify "
          "a secret key file instead.\n");
      exit(EXIT_FAILURE);
    }

    // check size
    if (s.st_size < KEY_BYTES) {
      fprintf(stderr, "Key file is too small. It must contain at "
          "least %d bytes.\n", KEY_BYTES);
      exit(EXIT_FAILURE);
    }

    // read key
    if (fread(key, KEY_BYTES, 1, f) == 0) {
      perror("Couldn't read key file");
      exit(EXIT_FAILURE);
    }
  }
  fclose(f);
}

void get_key_from_str(const char *str, uint8_t *key) {
  size_t bin_len, bytes_read;
  const char * hex_end; // pointer to last parsed hex character

  if (-1 == sodium_hex2bin(key, KEY_BYTES, str,
        strlen(str), ":", &bin_len, &hex_end)) {
    fprintf(stderr, "Given key is too long, only %u bytes are useable!\n",
        KEY_BYTES);
    exit(EXIT_FAILURE);
  }

  /* check if invalid characters (like "abfg") or invalid format given (like
   * "abc", which has an uneven number of 4-bit nibbles)
   */
  if ((hex_end - str) < strlen(str)) {
    fprintf(stderr, "Please check your key for typos.\n");
    exit(EXIT_FAILURE);
  }

  /* warn about short keys */
  if (bin_len < KEY_BYTES)
    fprintf(stderr, "WARNING: reuising key material to make up a key "
        "of sufficient length\n");
    bytes_read = bin_len;
    while (bytes_read < KEY_BYTES) {
      sodium_hex2bin(&key[bytes_read], KEY_BYTES - bytes_read,
        str, strlen(str), ": ", &bin_len, NULL);
      bytes_read += bin_len;
    }
}

char *read_line(char *buf, size_t len)
  /* Read at most len characters from stdin and writes them to buf.  If the
   * input line contains more characters, discard the rest.
   *
   * Returns a null pointer on error.
   *
   * Taken from http://home.datacomm.ch/t_wolf/tw/c/getting_input.html
   */
{
  char *p;

  if ((p = fgets(buf, len, stdin)) != NULL) {
    size_t last = strlen (buf) - 1;

    if (buf[last] == '\n') {
      /**** Discard the trailing newline */
      buf[last] = '\0';
    } else {
      /**** There's no newline in the buffer, therefore there must be
            more characters on that line: discard them!
       */
      fscanf (stdin, "%*[^\n]");
      /**** And also discard the newline... */
      (void) fgetc (stdin);
    } /* end if */
  } else {
    /* p == NULL, which means 0 bytes read before EOF or read error */
  }
  return p;
}

/* must be at least 2*32+31+1=96 (2*32 hex + upto 31 ':' + '\n') but longer is
 * better so get_key_from_str() can nicely inform about a too long key.
 *
 * Using 97 would work in most cases, but there might be sequences like ":::"
 * in the key, which don't add any more bytes to the binary key.
 */
#define HEX_KEY_MAXLEN (128)
void get_key(const struct arguments * const arguments, uint8_t key[KEY_BYTES]) {
  switch (arguments->key_source) {
    case RANDOM:
      randombytes_buf(key, KEY_BYTES);
      char hex[KEY_BYTES * 2 + 1];
      sodium_bin2hex(hex, KEY_BYTES * 2 + 1, key, KEY_BYTES);
      fprintf(stderr, "%s\n", hex);
      break;
    case KEY_FILE:
      get_key_from_file(arguments->key_file, key);
      break;
    case CMD:
      get_key_from_str(arguments->key, key);
      break;
    case ASK:
      fprintf (stderr, "Enter key: ");
      fflush (stderr);
      char *hex_key = sodium_malloc(HEX_KEY_MAXLEN);
      if (hex_key == NULL) {
        fprintf(stderr, "Memory for prompted key couldn't be allocated.\n");
        exit(EXIT_FAILURE);
      }
      if (read_line(hex_key, HEX_KEY_MAXLEN) == NULL) {
        sodium_free(hex_key);
        fprintf(stderr, "Error while reading key from stdin.\n");
        exit(EXIT_FAILURE);
      }
      get_key_from_str(hex_key, key);
      sodium_free(hex_key);
      break;
  }
  DEBUG_ONLY(hexDump("not so secret key", key, KEY_BYTES));
}

void key_munlock(void) {
  sodium_munlock(key, sizeof key);
}

void key_mlock(void) {
  if (sodium_mlock(key, sizeof key) == -1) {
    fprintf(stderr, "Unable to lock memory for key.\n");
    exit(EXIT_FAILURE);
  }

  /* register unlocking before exit
   * NOTE: This is important because the unlocking also zeroes the memory out
   * before actually unlocking it. */
  atexit(key_munlock);
}

FILE* open_input(struct arguments *arguments) {
  if (arguments->input_source == INPUT_FILE) {
    FILE *input = fopen(arguments->input_file, "r");
    if (input == NULL) {
      perror("Couldn't open input file");
      exit(EXIT_FAILURE);
    }
    return input;
  } else {
    return stdin;
  }
}

void close_input(FILE *input) {
  if (input == stdin) return;
  fclose(input);
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
