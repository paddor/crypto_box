#ifndef DECRYPTION_H
#define DECRYPTION_H
#include "config.h"
#include "util.h"
#include "chunk.h"
#include <err.h>
#include <sysexits.h>
#include <stdio.h>
#include <stdint.h>
#include <sodium.h>

extern void open_box(FILE *input, FILE *output, uint8_t const * const key,
		bool hex);

// vim: et:ts=2:sw=2
#endif
