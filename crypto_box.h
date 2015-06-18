#ifndef CRYPTO_BOX_H
#define CRYPTO_BOX_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sodium.h>

#ifdef DEBUG
  #define DEBUG_ONLY(x) (x)
#else
  #define DEBUG_ONLY(x)
#endif

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


#define INITIAL_CT_SIZE 512
#define KEY_BYTES crypto_secretbox_KEYBYTES
#define MAC_BYTES crypto_secretbox_MACBYTES
#define NONCE_BYTES crypto_secretbox_NONCEBYTES
#define CT_AFTER_MAC(x) (x+MAC_BYTES)
#define PT_LEN(x) (x-MAC_BYTES)
#define READ_BYTES 128

typedef struct {
  uint8_t *data;
  size_t used;
  size_t size;
} ct_t;

static uint8_t key[KEY_BYTES];
static uint8_t nonce[NONCE_BYTES];
static ct_t ct;
static enum { BIN, HEX } ciphertext = BIN;
static enum { RANDOM, CMD, ASK } key_source = RANDOM;

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

#endif
// vim: et:ts=2:sw=2
