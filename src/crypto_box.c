#include "crypto_box.h"

void crypto_box_init(void) {
  if (sodium_init() == -1) {
    fprintf(stderr, "unable to initialize libsodium\n");
    exit(EXIT_FAILURE);
  }
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
