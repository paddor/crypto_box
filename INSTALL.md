# Dependencies

# Runtime
* libsodium (on Mac: `brew install libsodium`)
* Mac only: argp (`brew install argp-standalone`)

# Development (and running the test suite)
* Check (on Mac: `brew install check`)

# Installation
This project uses GNU autotools for now. I'm planning to switch to CMake.
```
tar xf crypto_box-*.tar.gz
cd crypto_box-*
./configure
make && make install
```
