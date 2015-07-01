# Crypto Box
Simple secret-key encryption without the PGP/GPG/OpenSSL/OMG jungle. Secure by
default by leveraging [libsodium](https://github.com/jedisct1/libsodium)'s
power.

## Usage

Crypto Box gives you two (filter) utilities: `lock_box` and `open_box`. These
have been developed with the Unix philosophy _Do one thing and do it well_ in
mind.  They are very simple to use, but that doesn't mean you can't do anything
wrong.  As always, it's your responsibility to keep a secret key secret.

### Encryption: `lock_box`

Reads plaintext from STDIN and writes ciphertext to STDOUT. Below are the
different ways of specifying a key. The ciphertext will be sightly larger than
the plaintext since it'll contain a nonce (24 bytes) and MAC (16 bytes) for
each chunk and one more trailing MAC (16 bytes). See Internals.

#### Random key (no key file)

If no options are given, a random key is generated and printed on STDERR. It
will not be automatically stored anywhere. This is only safe to use locally or
over secure connections like SSH (and nobody looking over your shoulders).

```
$ echo foobar | lock_box > locked.box
4a5c4119c24b0db47bb4b4d8383c716ea390f04553f8877d0c94099e1ac12eb6
$ ls -l locked.box
-rw-r--r--+ 1 user  staff  47 Jun 18 12:20 locked.box
```
The output file in this case is 24+16+7+16=63 bytes long, for nonce, chunk MAC,
ciphertext, trailing MAC, respectively.

The long hex string is the randomly generated key. Store it somewhere safe and
**keep it secret**.

To decrypt a box later, specify the key directly on the command line or use
`-a`/`--ask` (see below).

#### Key file

Use the option `-k`/`--key-file` to specify a key file. **Note**: If the key
file doesn't exist yet, a randomly generated key will be used and stored into
that file.  Only use this if your key file will be located on an encrypted
disk.

```
$ ls -l secret.key
ls: secret.key: No such file or directory
$ echo foobar | lock_box -k secret.key > locked.box
$ ls -l locked.box secret.key
-rw-r--r--+ 1 user  staff  47 Jun 18 19:31 locked.box
-r--------+ 1 user  staff  47 Jun 18 19:31 secret.key
```

If the key file already exists, its first 32 bytes are used as the key.
**Note**: Crypto Box will refuse to use a key file that permits access to
anyone else but the owner.

```
$ ls -l *secret.key
-rw-r--r--+ 1 user  staff  47 Jun 18 19:29 not_so_secret.key
$ echo foobar | lock_box -k not_so_secret.key > locked.box
Please specify a *secret* key file.
```

Keep in mind that, on a shared system, the administrator (`root`) can still
read your key file.  Hell, anybody is still able to read your key file if your
system sucks (security vulnerabilities, physical access but no disk
encryption, ...).

#### Key as command line argument

You can specify a key on the command line, using hex ASCII characters (`0-9a-f`).
This can be useful if you let `lock_box` generate a random key earlier without
storing it to a key file or you've kept it as a piece of information outside
your computer.

If you do this, **make sure your command won't get logged**! Enable the option
`hist_ignore_space` in Zsh or `ignore_space` in Bash.

```
# notice the additional space before the whole command, so it won't get logged
$  echo foobar | lock_box abba0ff887ca6064622b30a47a2aa9980faa1f544b24a9991b14e948d7331728 > locked.box
$ ls -l locked.box
-rw-r--r--+ 1 user  staff  47 Jun 18 12:22 locked.box
```

Colons (`:`) in the key are ignored, so you can also specify the key like this: `ab:ba:0f:f8:87:ca:60:64:62:2b:30:a4:7a:2a:a9:98:0f:aa:1f:54:4b:24:a9:99:1b:14:e9:48:d7:33:17:28`.

A key shorter than 32 byte (which would be at least 64 ASCII hex characters)
will be repeated to make up a complete 32 byte key. This is **not
recommended**, as it greatly decreases the information content of the key,
which makes it easier to guess.

```
$  echo foobar | lock_box 6ea390f04553 > insecurely_locked.box
WARNING: reuising key material to make up a key of sufficient length
$ ls -l locked.box
-rw-r--r--+ 1 user  staff  47 Jun 18 12:24 insecurely_locked.box
```

#### Prompting for the key

Use the option `-a`/`--ask` to be prompted for a key. In this case, you have to
specify the input file with `-f`/`--file`, as STDIN is already used to get the
key.  This can be useful if you're worried about your command being logged in
your shell's history.

```
$ echo foobar > secret.txt
$ lock_box --ask --file secret.txt > secret.box
Enter key: 
```

Don't forget to delete your plaintext file after encrypting it! ;-) Or avoid
creating a file altogether with some shell magic:

```
$ lock_box -af <(echo foobar) > secret.box
Enter key: 
```

### Decryption: `open_box`

Reads ciphertext from STDIN and writes plaintext to STDOUT. The
key can be given in the same ways as for `lock_box`. Here's an example using a
key file:

```
$ open_box -k secret.key < locked.box
foobar
```

In case the box has been tampered with, MAC verification will fail and the
program will exit with a message on STDERR. Example:

```
$ echo foobar | lock_box -k secret.key > locked.box
$ ls -l locked.box secret.key
-rw-r--r--+ 1 user  staff  47 Jun 18 12:27 locked.box
-r--------+ 1 user  staff  47 Jun 18 12:27 secret.key
$ echo "baz" >> locked.box
$ ls -l locked.box
-rw-r--r--+ 1 user  staff  51 Jun 18 12:27 locked.box
$ open_box -k secret.key < locked.box
Ciphertext couldn't be verified. It has been tampered with or you're using the wrong key.
```

## Internals

### Primitives
As mentioned above, libsodium is used to do
encryption/decryption/authentication. The cryptographic primitives used are
XSalsa20 and Poly1305.

XSalsa20 (with its 24 byte nonces) is a good choice because it allows one to
safely use randomly generated nonces. Of course, the full 20-rounds version of
XSalsa20 is used.

Poly1305 will ensure the integrity of your data. Never use encryption without
authentication to verify the integrity of the encrypted data. If you don't care
if someone tampers with your data, you might as well just send plaintext.

### Memory locking
The memory used for the secret key is locked before the key is stored in it and
zeroed out and unlocked before the programs exit. This applies to the randomly
generated key and the one given on STDIN (with `-a`/`--ask`). It doesn't apply
to the one given on the command line (see TODO).

### Chunking
Encryption and decryption are done in chunks. This means that only a small
amount of memory is used, no matter how big the input is. Each chunk is
encrypted using a new nonce and authenticated with a MAC. That means that,
during encryption, 16+24=40 additional bytes will be added for each chunk
(instead of once for the whole file like in versions before 0.4.0).

The chunk size is 64KB (or less for the last chunk, depending on input size).
According to benchmarks using a file of ~155MB, this chunk size is big enough
to make both speed and size overheads negligible.

To avoid missing/reordered/replayed chunks going undetected, an additional,
trailing MAC is appended, which authenticates all previous MACs. The nonce to
derive the subkey for the MAC of MACs, an additional nonce of 24 bytes is
prepended at the very beginning of the ciphertext, so `open_box` can start
calculating the MAC of MACs right away during decryption.

All in all, this is how the output of `lock_box` including all MACs and nonces
will look like:

```
+----------------------+---------------------------------+----------------+
|   nonce (24 bytes)   |    variable number of chunks    | MAC (16 bytes) |
+----------------------+---------------------------------+----------------+
```

Whereas each chunk looks like this:

```
+----------------------+----------------+-------------------------------+
|   nonce (24 bytes)   | MAC (16 bytes) |    ciphertext (up to 64KB)    |
+----------------------+----------------+-------------------------------+
```


## TODO

* fail early if ciphertext has been tampered with
  - MAC authenticates previous MAC
  - first and last chunks are marked as such
  - this also gets rid of the additional nonce and MAC pair around the whole
    ciphertext
* lock and zero out key in arguments (possible?)
* test suite
* switch to CMake
* K&R style function definitions
* explicit creation of key file to avoid an attacker to create a key file
  - -K/--new-key-file
* hex ciphertext (-H)

## License

ISC. See LICENSE file.
