News for Crypto Box 0.7.0
=========================
* All warnings and error messages are now prepended by the program name.
* Some typos in warnings fixed.
* Much cleaner code.
* More tests.

News for Crypto Box 0.6.1
=========================
* Fixed a problem with older versions of CMake fixed (like 2.8.12).

News for Crypto Box 0.6.0
=========================
* Changed chunk size back to 64 KiB, as it performs much better with the common
  pipeline buffers size of 64 KiB.
* Option `-H`/`--hex` is now implemented. It'll write/read ciphertext in hex.
* Better help: Additional usages and a more detailed section below the options.
* New values for chunk type. Decrypt old boxes first before upgrading.
* The build system used is now CMake, not Autotools anymore. You'll notice a
  different installation procedure.
* There's a test suite now. It verifies that the code works as expected.
* Continuous Integration: The test suite is run by Travis CI, drone.io and
  semaphoreci every time new commits are pushed. One of these would be enough,
  but I'm still playing around to get a feeling of all of them.
* Source split up into functionally coherent files.

News for Crypto Box 0.5.0
=========================
* Increased chunk size from 64 KiB to 256 KiB
* More space efficient output format: A single nonce and no more MAC of MACs.

News for Crypto Box 0.4.0
=========================
* Now the programs encrypt and decrypt in chunks. Encrypting a 100GB file is
  now possible with just a few KB of RAM! See README for details.

News for Crypto Box 0.3.0
=========================
* Fixed segfault when open_box is used without specifying a key.
* The option `-a`/`--ask` is now implemented. Option `-f`/`--file` has been
  added, because `-a`/`--ask` doesn't make sense otherwise.
* Now the programs warn and abort if a key given on the command line contains
  invalid characters (like "abcx") or has an incorrect format (like "abc").
* A warning is issued before writing ciphertext to terminal.


News for Crypto Box 0.2.0
=========================
* Added option `-k`/`--key-file` to support getting the key from the first 32
  bytes of a file. If the file doesn't exist, it'll be created and a newly
  generated key will be stored into it.
