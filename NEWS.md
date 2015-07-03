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
