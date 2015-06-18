CC=llvm-gcc
INCLUDES=
CFLAGS=$(shell pkg-config --cflags libsodium) -Wall -std=c11
LDFLAGS=$(shell pkg-config --libs libsodium)

DEBUG ?= 1
ifeq ($(DEBUG), 1)
	CFLAGS+= -DDEBUG -g
endif

default: all
all:	seal_box open_box

seal_box: crypto_box.c crypto_box.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

open_box: crypto_open.c crypto_box.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -f seal_box open_box
	rm -rf *.dSYM
