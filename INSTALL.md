# Installation

## Dependencies

### Runtime
* libsodium (on OSX: `brew install libsodium`)
* OSX/BSD only: argp (on OSX: `brew install argp-standalone`)

### Compilation
* CMake (on OSX: `brew install cmake`)

### Development (and running `make test`)
* Check (on OSX: `brew install check`)

## Procedure

### Unpack sources

Replace `VERSION` with the actual version.

```
tar xf crypto_box-VERSION-Source.tar.xz
```

### Create build directory

Create and cd into some build directory. Building outside the source tree is considered cleaner than building in-source.

```
mkdir crypto_box_build && cd crypto_box_build
```

### Generate Makefile

Again, replace `VERSION` with the actual version.

```
cmake -D CMAKE_BUILD_TYPE=Release ../crypto_box-VERSION-Source
```

### Compile and install

```
make && make install
```

If you have Check installed, you can run the test suite before installing.

```
make && make test && make install
```
