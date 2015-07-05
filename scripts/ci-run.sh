#!/bin/bash
mkdir -p build/test && cd build/test
cmake ../..
make VERBOSE=1 check_sanity check_sodium_sanity
make test
