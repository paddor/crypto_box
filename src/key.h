#ifndef KEY_H
#define KEY_H
#include "crypto_box.h"

#define KEY_BYTES crypto_stream_xsalsa20_KEYBYTES

int key_malloc(uint8_t ** const key);
void get_key(const struct arguments * const arguments, uint8_t key[KEY_BYTES]);

// vim: et:ts=2:sw=2
#endif
