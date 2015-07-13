#include "key.h"

static void
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

static void
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

static char *
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

int
key_malloc(uint8_t ** const key)
{
  *key = sodium_malloc(KEY_BYTES);
  if (*key == NULL) {
    fprintf(stderr, "Unable to allocate memory for key.\n");
    return -1;
  }

  return 0;
}
// vim: et:ts=2:sw=2
