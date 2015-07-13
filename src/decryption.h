#ifndef DECRYPTION_H
#define DECRYPTION_H
#include "crypto_box.h"
#include "chunk.h"

extern void open_box(FILE *input, FILE *output, uint8_t const * const key);

// vim: et:ts=2:sw=2
#endif
