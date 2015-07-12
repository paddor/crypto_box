#ifndef DECRYPTION_H
#define DECRYPTION_H
#include "crypto_box.h"
#include "chunk.h"
#include "key.h"

extern void open_box(FILE *input, FILE *output);

// vim: et:ts=2:sw=2
#endif
