#ifndef ENCRYPTION_H
#define ENCRYPTION_H
#include "crypto_box.h"
#include "util.h"
#include "chunk.h"

extern void lock_box(FILE *input, FILE *output, uint8_t const * const key);

// vim: et:ts=2:sw=2
#endif
