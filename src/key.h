#ifndef KEY_H
#define KEY_H
#include "crypto_box.h"
#include "arguments.h"

int key_malloc(uint8_t ** const key);
void get_key(const struct arguments * const arguments, uint8_t * const key);

// vim: et:ts=2:sw=2
#endif
