#include "key.h"

static void
get_key_from_file(const char *key_file, uint8_t *key)
{
  FILE *f = fopen(key_file, "r");
  if (f == NULL && errno != ENOENT) err(EX_NOINPUT, "Couldn't open key file");

  if (f == NULL && errno == ENOENT) {
    /* Create a new key file. */

    int fd = open(key_file, O_WRONLY | O_CREAT | O_EXCL, 0400);
    if (fd == -1) err(EX_CANTCREAT, "Couldn't create key file");

    f = fdopen(fd, "w");
    if (f == NULL)
      err(EX_OSERR, "Couldn't associate stream with file descriptor");

    randombytes_buf(key, crypto_stream_xsalsa20_KEYBYTES); // random key
    if (fwrite(key, crypto_stream_xsalsa20_KEYBYTES, 1, f) == 0) {
      err(EX_IOERR, "Couldn't write key file");
    }
  } else {
    /* Use existing key file. */

    struct stat s;
    if (fstat(fileno(f), &s) != 0) err(EX_OSERR, "Couldn't stat key file");

    // check file permissions
    if ((s.st_mode & 077) > 0) {
      errx(EX_DATAERR, "Please specify a *secret* key file.");
    }

    // check size
    if (s.st_size < crypto_stream_xsalsa20_KEYBYTES) {
      errx(EX_DATAERR, "Key file is too small. It must contain at "
          "least %d bytes.", crypto_stream_xsalsa20_KEYBYTES);
    }

    // read key
    if (fread(key, crypto_stream_xsalsa20_KEYBYTES, 1, f) == 0)
      err(EX_IOERR, "Couldn't read key file");
  }
  fclose(f);
}

static void
get_key_from_str(const char *str, uint8_t *key)
{
  size_t bin_len, bytes_read;
  const char * hex_end; // pointer to last parsed hex character

  if (-1 == sodium_hex2bin(key, crypto_stream_xsalsa20_KEYBYTES, str,
        strlen(str), ":", &bin_len, &hex_end)) {
    errx(EX_USAGE, "Given key is too long, only %u bytes are useable!",
        crypto_stream_xsalsa20_KEYBYTES);
  }

  /* check if invalid characters (like "abfg") or invalid format given (like
   * "abc", which has an uneven number of 4-bit nibbles)
   */
  if ((hex_end - str) < strlen(str))
    errx(EX_USAGE, "Please check your key for typos.");

  /* warn about short keys */
  if (bin_len < crypto_stream_xsalsa20_KEYBYTES)
    warnx("Warning: Reusing key material to make up a complete key.");
    bytes_read = bin_len;
    while (bytes_read < crypto_stream_xsalsa20_KEYBYTES) {
      sodium_hex2bin(&key[bytes_read],
        crypto_stream_xsalsa20_KEYBYTES - bytes_read,
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
get_key(const struct arguments * const arguments, uint8_t * const key)
{
  switch (arguments->key_source) {
    case RANDOM:
      randombytes_buf(key, crypto_stream_xsalsa20_KEYBYTES);
      char hex[crypto_stream_xsalsa20_KEYBYTES * 2 + 1];
      sodium_bin2hex(hex, crypto_stream_xsalsa20_KEYBYTES * 2 + 1, key,
          crypto_stream_xsalsa20_KEYBYTES);
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
      fprintf(stderr, "Enter key: ");
      fflush(stderr);
      char *hex_key = sodium_malloc(HEX_KEY_MAXLEN);
      if (hex_key == NULL)
        errx(EX_OSERR, "Memory for prompted key couldn't be allocated.");

      if (read_line(hex_key, HEX_KEY_MAXLEN) == NULL) {
        sodium_free(hex_key);
        errx(EX_NOINPUT, "Error while reading key from stdin.");
      }
      get_key_from_str(hex_key, key);
      sodium_free(hex_key);
      break;
  }
}

void
key_malloc(uint8_t ** const key)
{
  *key = sodium_malloc(crypto_stream_xsalsa20_KEYBYTES);
  if (*key != NULL) return;
  errx(EX_OSERR, "Unable to allocate memory for key.");
}
// vim: et:ts=2:sw=2
