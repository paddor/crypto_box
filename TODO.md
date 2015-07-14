# TODO

* more tests
  - tampered ciphertext
    * incomplete chunk
    * completely missing chunk (head, middle, tail)
    * replaced byte sequence
    * truncated to < 17 bytes, 0 bytes
    * wrong chunk type
* (C11) threads to read, encrypt/decrypt, write in parallel
