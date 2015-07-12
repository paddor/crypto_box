#ifndef KEY_H
#define KEY_H
#include "crypto_box.h"

uint8_t *key;

uint8_t *key_malloc();
void get_key(const struct arguments * const arguments, uint8_t key[KEY_BYTES]);

// vim: et:ts=2:sw=2
#endif
