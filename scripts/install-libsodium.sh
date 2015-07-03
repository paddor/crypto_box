#!/bin/bash

# This is needed because Ubuntu precise (12.04 LTS) doesn't know libsodium yet
# and I don't wanna use wily (unstable) because CMake 3.3 is probably not even
# needed. I'll just go with Ubuntu trusty (14.04 LTS) to get CMake 2.8.12.

SODIUM_URL=https://github.com/jedisct1/libsodium/releases/download/1.0.3/libsodium-1.0.3.tar.gz
cd `mktemp -d /tmp/install-libsodium-XXXX`
wget $SODIUM_URL || exit 1
tar xf libsodium-*.tar.gz && cd libsodium-* || exit 1
./configure && make && make check && sudo make install || exit 1
