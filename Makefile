CC=llvm-gcc
INCLUDES=
CFLAGS=-Wall -std=c11 $(shell pkg-config --cflags libsodium) -g
LDFLAGS=$(shell pkg-config --libs libsodium)

default: crypto_box crypto_open

crypto_box: crypto_box.h crypto_box.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ crypto_box.c

crypto_open: crypto_box.h crypto_open.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ crypto_open.c

.PHONY: clean
clean:
	rm -f crypto_box crypto_open
