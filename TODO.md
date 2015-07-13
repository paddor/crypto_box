# TODO

* `cb_` prefix for functions ("crypto box")
* more tests
  - tampered ciphertext
    * appended chunk
    * incomplete chunk
    * completely missing chunk (head, middle, tail)
    * replaced byte sequence
    * truncated to < 17 bytes, 0 bytes
    * no nonce
    * wrong chunk type
* (C11) threads
