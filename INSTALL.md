# Dependencies
* libsodium (on Mac: `brew install libsodium`)

# Installation
This project uses GNU autotools for now. I'm planning to switch to CMake.
```
tar xf crypto_box-*.tar.gz
cd crypto_box-*
./configure
make && make install
```
