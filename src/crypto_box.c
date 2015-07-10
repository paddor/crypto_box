#include "crypto_box.h"

void
init_chunk(struct chunk *chunk)
{
  /* we allocate CHUNK_CT_BYTES, which is the maximum of data needed, and
   * slightly bigger than CHUNK_PT_BYTES
   */
  chunk->data = malloc(CHUNK_CT_BYTES * sizeof *chunk->data);
  if (chunk->data == NULL) {
    fprintf(stderr, "chunk data couldn't be allocated\n");
    exit(EXIT_FAILURE);
  }
  chunk->used = 0;
  chunk->size = CHUNK_CT_BYTES;
}

void
free_chunk(struct chunk *chunk)
{
  free(chunk->data);
  chunk->data = NULL;
  chunk->used = 0;
  chunk->size = 0;
}

/* allocate memory for authentication subkey */
unsigned char *
auth_subkey_malloc()
{
  unsigned char *subkey = sodium_malloc(crypto_onetimeauth_KEYBYTES);
  if (subkey == NULL) {
    fprintf(stderr, "Memory for authentication subkey couldn't be "
        "allocated.\n");
    exit(EXIT_FAILURE);
  }
  return subkey;
}


int8_t
determine_chunk_type(size_t nread, size_t chunk_bytes,
    _Bool is_first_chunk, FILE *input)
{

  int c;
  uint8_t chunk_type = 0; /* nothing special about this chunk for now */
  if (nread == chunk_bytes) {
    /* check if we're right before EOF */
    if ((c = getc(input)) == EOF) {
      /* this is the last chunk */
      chunk_type = LAST_CHUNK;
    } else {
      /* not the last chunk, put character back */
      if (ungetc(c, input) == EOF) {
        fprintf(stderr, "Couldn't put character back.\n");
        return -1;
      }

      /* might be the first */
      if (is_first_chunk) chunk_type = FIRST_CHUNK;
    }
  } else if (feof(input)) { /* already hit EOF */
     /* this is the last chunk */
    chunk_type = LAST_CHUNK;
  } else if (is_first_chunk) {
    /* Since fread() guarantees that it reads the specified number of bytes
     * if possible, this code should never be reached. If fread() read less
     * bytes, it must have hit EOF already, which is handled above.
     *
     * But what the hell. Better be safe.
     */
    chunk_type = FIRST_CHUNK;
  }
  return chunk_type;
}

const char *argp_program_version = PACKAGE_STRING;
static char doc[] =
  PACKAGE_SUMMARY
  "\vlock_box:\n"
  "Reads plaintext from STDIN and writes ciphertext to STDOUT.\n"
  "The ciphertext will be sightly larger than the plaintext. In the first\n"
  "form, a randomly generated key will be used. The key will be printed to\n"
  "STDOUT in hex format.\n"
  "\n"
  "open_box:\n"
  "Reads ciphertext from STDIN and writes plaintext to STDOUT.\n"
  "\n"
  "For further details, please go to " PACKAGE_URL ".\n"
  "\n"
  "Please repport issues on " PACKAGE_BUGREPORT ".\n";
static char args_doc[] =
  "\n"
  "<key>\n"
  "--key-file <key_file>\n"
  "--ask --file <input_file>";
static struct argp_option options[] = {
    { "key-file", 'k', "FILE", 0, "get key from file"},
    { "ask", 'a', 0, 0, "Ask for the key (requires -f)"},
    { "file", 'f', "FILE", 0, "get data from file instead of STDIN"},
    { "hex", 'H', 0, 0, "read/write ciphertext as ASCII hex characters"},
    { 0 }
};

/* initialize with default values */
struct arguments arguments = { .input_source = STDIN, .ct_format = BIN };

error_t
parse_options(int key, char *arg, struct argp_state *state)
{
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

    if (arguments->key_source == CMD && arguments->key == NULL) {
      fprintf(stderr, "Please specify a key.\n");
      exit(EXIT_FAILURE);
    }
  default: return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

struct argp argp_parser = { options, parse_options, args_doc, doc, 0, 0, 0 };

void
get_key_from_file(const char *key_file, uint8_t *key)
{
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
      fprintf(stderr, "Please specify a *secret* key file.\n");
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

void
get_key_from_str(const char *str, uint8_t *key)
{
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

char *
read_line(char *buf, size_t len)
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
void
get_key(const struct arguments * const arguments, uint8_t key[KEY_BYTES])
{
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
      sodium_memzero(arguments->key, strlen(arguments->key));
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

void
key_free(void)
{
  sodium_free(key);
}

uint8_t *
key_malloc()
{
  uint8_t *key = sodium_malloc(KEY_BYTES);
  if (key == NULL) {
    fprintf(stderr, "Unable to allocate memory for key.\n");
    exit(EXIT_FAILURE);
  }

  /* register call to sodium_free() before exit
   * NOTE: This is important because the unlocking also zeroes the memory out
   * before actually unlocking and freeing it. */
  atexit(key_free);

  return key;
}

FILE*
open_input(struct arguments *arguments)
{
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

void
close_input(FILE *input)
{
  if (input == stdin) return;
  fclose(input);
}

void
lock_box(FILE *input, FILE *output)
{
  uint8_t nonce[NONCE_BYTES];
  uint8_t * nonce_hex;
  struct chunk chunk;
  size_t nread;
  int8_t chunk_type; /* first, last or in between */
  _Bool is_first_chunk = true;
  unsigned char *subkey;
  unsigned char previous_mac[MAC_BYTES];
  crypto_onetimeauth_state auth_state;

  subkey = auth_subkey_malloc();

  if (isatty(fileno(output)) && arguments.ct_format == BIN)
    fprintf(stderr, "WARNING: Writing binary ciphertext to terminal.\n");

  /* new nonce */
  randombytes_buf(nonce, sizeof nonce);
  DEBUG_ONLY(hexDump("nonce", nonce, sizeof nonce));

  /* print nonce */
  switch (arguments.ct_format) {
    case BIN:
      if (fwrite(nonce, sizeof nonce, 1, output) < 1) {
        perror("Couldn't write ciphertext");
        goto abort;
      }
      break;
    case HEX:
      nonce_hex = sodium_malloc(2 * sizeof nonce + 1);
      if (nonce_hex == NULL) {
        fprintf(stderr, "Couldn't allocate memory for hex nonce.\n");
        goto abort;
      }
      if (NULL == sodium_bin2hex((char *) nonce_hex, 2 * sizeof nonce + 1, nonce,
            sizeof nonce)) {
        fprintf(stderr, "Couldn't convert nonce to hex.\n");
        sodium_free(nonce_hex);
        goto abort;

      }
      if (fwrite(nonce_hex, 2 * sizeof nonce, 1, output) < 1) {
        perror("Couldn't write ciphertext");
        sodium_free(nonce_hex);
        goto abort;
      }
      sodium_free(nonce_hex);
      break;
  }

  init_chunk(&chunk);
  while(!feof(input)) {
    /* recycle chunk */
    chunk.used = MAC_BYTES + 1; /* reserve room for MAC + chunk_type */

    /* read complete chunk, if possible */
    nread = fread(&chunk.data[chunk.used], sizeof *chunk.data, CHUNK_PT_BYTES,
        input);
    chunk.used += nread;
    if (nread < CHUNK_PT_BYTES && ferror(input)) {
      fprintf(stderr, "Couldn't read plaintext.\n");
      goto abort;
    }
    DEBUG_ONLY(hexDump("read plaintext chunk",
          CHUNK_PT(chunk.data), CHUNK_PT_LEN(chunk.used)));

    chunk_type = determine_chunk_type(nread, CHUNK_PT_BYTES, is_first_chunk,
        input);
    if (chunk_type == -1) goto abort;

    /* set chunk type */
    chunk.data[CHUNK_TYPE_INDEX] = chunk_type;
    DEBUG_ONLY(hexDump("chunk type", &chunk.data[CHUNK_TYPE_INDEX], 1));

    /* encrypt chunk_type and plaintext (in-place) */
    crypto_stream_xsalsa20_xor_ic(CHUNK_CT(chunk.data), CHUNK_CT(chunk.data),
        CHUNK_CT_LEN(chunk.used), nonce, 1, key); /* 1 = initial counter */
    DEBUG_ONLY(hexDump("ciphertext chunk", CHUNK_CT(chunk.data),
          CHUNK_CT_LEN(chunk.used)));

    /* compute MAC */
    crypto_stream(subkey, sizeof subkey, nonce, key); /* new subkey */
    crypto_onetimeauth_init(&auth_state, subkey);
    crypto_onetimeauth_update(&auth_state, CHUNK_CT(chunk.data),
        CHUNK_CT_LEN(chunk.used));
    if (!is_first_chunk) {
      /* include previous MAC */
      crypto_onetimeauth_update(&auth_state, previous_mac, MAC_BYTES);
    }
    DEBUG_ONLY(hexDump("chunk MAC", CHUNK_MAC(chunk.data), MAC_BYTES));
    crypto_onetimeauth_final(&auth_state, CHUNK_MAC(chunk.data));
    memcpy(previous_mac, CHUNK_MAC(chunk.data), MAC_BYTES); /* remember MAC */

    /* print MAC + chunk_type + ciphertext */
    switch (arguments.ct_format) {
      case BIN:
        if (fwrite(chunk.data, chunk.used, 1, output) < 1) {
          perror("Couldn't write ciphertext");
          goto abort;
        }
        break;
      case HEX:
        for(size_t i = 0; i < chunk.used; ++i) {
          int ret = fprintf(output, "%02hhx", chunk.data[i]);
          if (ret < 0) {
            perror("Couldn't write ciphertext");
            goto abort;
          }
        }
        break;
    }

    /* increment nonce */
    sodium_increment(nonce, sizeof nonce);

    /* not first chunk anymore */
    is_first_chunk = false;
  }
  sodium_free(subkey);
  free_chunk(&chunk);
  return;

abort:
  sodium_free(subkey);
  free_chunk(&chunk);
  exit(EXIT_FAILURE);
}

void
open_box(FILE *input, FILE *output)
{
  uint8_t nonce[NONCE_BYTES];
  struct chunk chunk;
  size_t nread;
  int8_t chunk_type; /* what it should be, from open_box's view */
  _Bool is_first_chunk = true;
  unsigned char *subkey;
  unsigned char mac_should[MAC_BYTES];
  unsigned char previous_mac[MAC_BYTES];
  crypto_onetimeauth_state auth_state;

  subkey = auth_subkey_malloc();

  /* read nonce */
  switch (arguments.ct_format) {
    case BIN:
      if (fread(&nonce, sizeof nonce, 1, input) < 1) {
        fprintf(stderr, "Couldn't read ciphertext.\n");
        exit(EXIT_FAILURE);
      }
      break;
    case HEX:
      for(size_t i = 0; i < sizeof nonce; ++i) {
        int ret = fscanf(input, "%2hhx", nonce+i);
        if(ret == EOF) {
          perror("Couldn't read ciphertext.");
          exit(EXIT_FAILURE);
        }
      }
      break;
  }

  init_chunk(&chunk);
  while(!feof(input)) {
    /* recycle chunk */
    chunk.used = 0;

    /* read complete chunk, if possible */
    switch (arguments.ct_format) {
      case BIN:
        nread = fread(&chunk.data[chunk.used], sizeof *chunk.data,
            CHUNK_CT_BYTES, input);
        break;
      case HEX:
        nread = 0;
        for(size_t i = 0; i < CHUNK_CT_BYTES; ++i) {
          if (fscanf(input, "%2hhx", &chunk.data[chunk.used + i]) == 1)
            ++nread;
          else
            break;
        }
        break;
    }
    chunk.used += nread;
    DEBUG_ONLY(hexDump("ciphertext chunk read", chunk.data, chunk.used));

    /* truncated header */
    if (nread <= 17) { /* MAC + chunk_type = 17 */
      fprintf(stderr, "Ciphertext's has been truncated.\n");
      goto abort;
    }

    if (nread < (CHUNK_CT_BYTES) && ferror(input)) {
      fprintf(stderr, "Couldn't read ciphertext.\n");
      goto abort;
    }

    chunk_type = determine_chunk_type(nread, CHUNK_CT_BYTES, is_first_chunk,
        input);
    if (chunk_type == -1) goto abort;

    /* compute MAC */
    crypto_stream(subkey, sizeof subkey, nonce, key); /* new subkey */
    crypto_onetimeauth_init(&auth_state, subkey);
    crypto_onetimeauth_update(&auth_state, CHUNK_CT(chunk.data),
        CHUNK_CT_LEN(chunk.used));
    if (!is_first_chunk) {
      /* include previous MAC */
      crypto_onetimeauth_update(&auth_state, previous_mac, MAC_BYTES);
    }
    DEBUG_ONLY(hexDump("calculated chunk MAC", CHUNK_MAC(chunk.data),
          MAC_BYTES));
    crypto_onetimeauth_final(&auth_state, mac_should);
    memcpy(previous_mac, mac_should, MAC_BYTES); /* remember MAC */

    /* verify MAC */
    if (sodium_memcmp(mac_should, CHUNK_MAC(chunk.data), MAC_BYTES) != 0) {
      fprintf(stderr, "Ciphertext couldn't be verified. It has been "
        "tampered with or you're using the wrong key.\n");
      goto abort;
    }

    /* decrypt */
    crypto_stream_xsalsa20_xor_ic(CHUNK_CT(chunk.data), CHUNK_CT(chunk.data),
        CHUNK_CT_LEN(chunk.used), nonce, 1, key); /* 1 = initial counter */
    DEBUG_ONLY(hexDump("plain text", CHUNK_PT(chunk.data),
        CHUNK_PT_LEN(chunk.used)));

    /* check chunk type */
    if (chunk.data[CHUNK_TYPE_INDEX] != chunk_type) {
      /* Tail truncation, is the only case that might go undetected through MAC
       * verification above. So let's print a nice error message.
       *
       * Any other case is impossible, as the previous MAC verification would
       * have detected it
       */
      if ((chunk.data[CHUNK_TYPE_INDEX] == 0 ||
            chunk.data[CHUNK_TYPE_INDEX] == FIRST_CHUNK)
          && chunk_type == LAST_CHUNK) {
        fprintf(stderr, "Ciphertext's has been truncated.\n");
      }

      goto abort;
    }

    /* print plaintext */
    if (fwrite(CHUNK_PT(chunk.data), CHUNK_PT_LEN(chunk.used), 1, output) < 1)
    {
      perror("Couldn't write plaintext");
      goto abort;
    }

    /* increment nonce */
    sodium_increment(nonce, sizeof nonce);

    /* not first chunk anymore */
    is_first_chunk = false;
  }

  sodium_free(subkey);
  free_chunk(&chunk);
  return;

abort:
  sodium_free(subkey);
  free_chunk(&chunk);
  exit(EXIT_FAILURE);
}

void
hexDump(const char *desc, const void *addr, size_t len)
{
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

/* TODO: Remove when libsodium 1.0.4 is out */
void
sodium_increment(unsigned char *n, const size_t nlen)
{
    size_t       i;
    unsigned int c = 1U << 8;

    for (i = (size_t) 0U; i < nlen; i++) {
        c >>= 8;
        c += n[i];
        n[i] = (unsigned char) c;
    }
}

// vim: et:ts=2:sw=2
