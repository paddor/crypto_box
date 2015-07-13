[![Build Status on Travis CI](https://travis-ci.org/paddor/crypto_box.png?branch=master)](https://travis-ci.org/paddor/crypto_box?branch=master)
[![Build Status on drone.io](https://drone.io/github.com/paddor/crypto_box/status.png)](https://drone.io/github.com/paddor/crypto_box/latest)
[![Build Status on semaphore](https://semaphoreci.com/api/v1/projects/d5f56226-394c-453a-83c7-757b11f9279f/474468/shields_badge.svg)](https://semaphoreci.com/paddor/crypto_box)
[![ISC License](https://img.shields.io/badge/license-ISC_License-blue.svg)](LICENSE)

# Crypto Box
Simple secret-key encryption without the PGP/GPG/OpenSSL/OMG jungle. Secure by
default by leveraging [libsodium](https://github.com/jedisct1/libsodium)'s
power.

## Installation
See [INSTALL.md](INSTALL.md).

## Usage

Crypto Box gives you two (filter) utilities: `lock_box` and `open_box`. These
have been developed with the Unix philosophy _Do one thing and do it well_ in
mind.  They are very simple to use, but that doesn't mean you can't do anything
wrong.  As always, it's your responsibility to keep a secret key secret.

### Encryption: `lock_box`

Reads plaintext from STDIN and writes ciphertext to STDOUT. Below are the
different ways of specifying a key. The ciphertext will be sightly larger than
the plaintext. See Internals.

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

### Memory Safety
The memory used for the secret key is locked before the key is stored in it and
zeroed out and unlocked before the programs exit. This applies to the randomly
generated key and the one given on STDIN (with `-a`/`--ask`). The key given as
a command line argument is zeroed out right after reading it (but not locked).

### Chunking
Encryption and decryption are done in chunks. This means that only a small
amount of memory is used, no matter how big the input is. Each chunk is
encrypted using a new nonce and authenticated with a MAC. However, only the
first nonce will be output. All further nonces can be calculated from the first
(simply increments).

Also, each chunk MAC will not only be computed over its ciphertext, but also
over the previous chunk's MAC to avoid missing/reordered/replayed chunks going
undetected. To know which chunks are the first and the last (to avoid
truncation going undetected), each chunk gets an additional byte to identify
its type. If there's only one chunk, it's marked as the last (so tail
truncation of all but the fist chunks can be detected).

That means that `lock_box` will output 24 additional bytes for the nonce plus
16+1=17 additional bytes for each chunk. Versions before 0.4.0 would output a
fixed number of 24+16=40 additional bytes for the whole input. According to
libsodium's documentation, one single MAC isn't suited for huge files.

The chunk size is 64 KiB (or less for the last chunk, depending on input
size).  This makes the speed and size overheads negligible and still allows a
tiny memory foot print.

Schematically, output from `lock_box` will look like this:
```
+-----------------------+----------------------------------------------------+
|    nonce (24 bytes)   |                  one or more chunks                |
+-----------------------+----------------------------------------------------+
```

Whereas each chunk will look like this:
```
+-------------------+------------+-------------------------------------------+
|  MAC (16 bytes)   | type (1 B) |     ciphertext (up to 64 KiB - 17 B)      |
+-------------------+------------+-------------------------------------------+
```

## Caveats

### Truncated ciphertext input produces incomplete plaintext output
it's possible that `open_box` will output data before it
eventually finds out that the ciphertext has been truncated. However, it will
**never ever** output any unauthenticated data. And, of course, when it
eventually finds out the ciphertext has been truncated, it exits immediately
with an error code.

In other words: Don't use Crypto Box if you're redirecting the plaintext to
another command which must never ever read a single byte of truncated plaintext
(even before it will be terminated right after `open_box` exits with an error
code).

**Reason**: In a pipeline, it's impossible to know how long the data from STDIN
is, unless you want to read everything into memory (or a temporary file) before
starting to write to STDOUT. Starting with 0.4.0, Crypto Box works in chunks to
keep a small memory footprint, no matter how large the input. That's why it
works like this.

### No padding
There's no padding involved, even when the plaintext input's length is 0. The
plaintext's length can be calculated from the ciphertext's length.

## Limitations
Due to the filter nature and lack of a header that specifies the length of the
data, there are real limitations in the length of a file/data stream you can
encrypt (at once). Of course, reasonable reuse of a key is advised.

To be precise: You could safely encrypt encrypt up to 3.347787592E35 YiB at
once with one key. That's a whole lot more than all of the WWW. And more than
ZFS can store.

Explanation: We have a 24 byte nonce. That nonce is used to encrypt one
chunk of 64 KiB. After that, the nonce is incremented for the next chunk. 24
bytes are 192 bit, so we have 2^192 different nonces for one key. Each nonce
can be used to encrypt up to 64 KiB. So:

```
2^192 * 64 KiB = 3.923188585E56 KiB
               = 3.831238852E53 MiB
               = 3.741444192E50 GiB
               = 3.653754093E47 TiB
               = 3.568119232E44 PiB
               = 3.484491437E41 EiB
               = 3.402823669E38 ZiB
               = 3.347787592E35 YiB
```

## News
See [NEWS.md](NEWS.md).

## TODO
See [TODO.md](TODO.md).

## License
See [LICENSE](LICENSE).
