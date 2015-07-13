#ifndef UTIL_H
#define UTIL_H
#include "crypto_box.h"
#include "arguments.h"

extern void crypto_box_init(void);
extern FILE* open_input(struct arguments *arguments);
extern void close_input(FILE *input);

/* TODO: Remove when libsodium 1.0.4 is out */
extern void sodium_increment(unsigned char *n, const size_t nlen);

// vim: et:ts=2:sw=2
#endif
