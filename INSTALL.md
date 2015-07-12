# Dependencies

# Runtime
* libsodium (on Mac: `brew install libsodium`)
* OSX/BSD only: argp (`brew install argp-standalone`)

# Development (and running `make test`)
* Check (on OSX: `brew install check`)

# Installation
This project uses CMake. Basic installation instructions:

```
tar xf crypto_box-0.6.0-Source.tar.xz
cd crypto_box-0.6.0-Source
cmake -D CMAKE_BUILD_TYPE=Release .
make && make install
```
