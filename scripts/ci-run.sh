#!/bin/bash
mkdir -p build/test && cd build/test || exit 1
cmake ../.. || exit 1
make VERBOSE=1 check_sanity check_sodium_sanity || exit 1
make test || exit 1
