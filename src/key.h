#ifndef KEY_H
#define KEY_H
#include "config.h"
#include "arguments.h"
#include <err.h>
#include <sysexits.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sodium.h>

int key_malloc(uint8_t ** const key);
void get_key(const struct arguments * const arguments, uint8_t * const key);

// vim: et:ts=2:sw=2
#endif
