# Crypto Box
Simple secret-key encryption without the PGP/GPG/OpenSSL/OMG jungle. Secure by
default by leveraging [libsodium](https://github.com/jedisct1/libsodium)'s
power.

This gives you two utilities: `seal_box` and `open_box`. These have been
developed with the Unix philosophy _Do one thing and do it well_ in mind.

## `seal_box`
Reads plaintext from STDIN and writes ciphertext (including MAC and nonce) to STDOUT.

### Random key
By default, it uses a randomly generated key and prints the key on STDERR.

```
$ echo foobar | seal_box > sealed.box
4a5c4119c24b0db47bb4b4d8383c716ea390f04553f8877d0c94099e1ac12eb6
$ ls -l sealed.box
-rw-r--r--+ 1 user  staff  47 Jun 18 12:20 sealed.box
```
The output file in this case is 7+16+24=47 bytes long, for ciphertext, MAC and
nonce, respectively.

The long hex string is the randomly generated key. Store it somewhere safe and
*keep it secret*.

### Key file (WIP)

Use the option `-k` to specify a key file.  If the key file doesn't exist yet,
a randomly generated key will be used and stored into that file.

```
$ ls -l secret.key
ls: secret.key: No such file or directory
$ echo foobar | seal_box -k secret.key > sealed.box
$ ls -l sealed.box secret.key
-rw-r--r--+ 1 user  staff  47 Jun 18 19:31 sealed.box
-r--------+ 1 user  staff  47 Jun 18 19:31 secret.key
```

If the key file already exists, its first 32 bytes are used as the key. Note
that a key file that is readable by anyone else but the owner will *not be
used*.

```
$ ls -l *secret.key
-rw-r--r--+ 1 user  staff  47 Jun 18 19:29 not_so_secret.key
$ echo foobar | seal_box -k not_so_secret.key > sealed.box
Key file is readable by other users! Please specify a secret key file instead.
```

Keep in mind that the administrator (`root`) can still read your key file.
Hell, anybody is still able to read your key file if your system sucks
(security vulnerabilities, physical access but no disk encryption, ...).

### Key as command line argument
You can specify a key on the command line, using hex ASCII characters (`0-9a-f`).
If you do this, *make sure your command won't get logged*! Enable the option
`hist_ignore_space` in Zsh or `ignore_space` in Bash.

```
# notice the additional space before the whole command, so it won't get logged
$  echo foobar | seal_box abba0ff887ca6064622b30a47a2aa9980faa1f544b24a9991b14e948d7331728 > sealed.box
$ ls -l sealed.box
-rw-r--r--+ 1 user  staff  47 Jun 18 12:22 sealed.box
```

Colons (`:`) in the key are ignored. So the following example is equivalent to
the one above:

```
$  echo foobar | seal_box ab:ba:0f:f8:87:ca:60:64:62:2b:30:a4:7a:2a:a9:98:0f:aa:1f:54:4b:24:a9:99:1b:14:e9:48:d7:33:17:28 > sealed.box
$ ls -l sealed.box
-rw-r--r--+ 1 user  staff  47 Jun 18 12:22 sealed.box
```
A key shorter than 32 byte (which would be at least 64 ASCII hex characters)
will be repeated to make up a complete 32 byte key. This is *not recommended*.

```
$  echo foobar | seal_box 6ea390f04553 > insecurely_sealed.box
WARNING: reuising key material to make up a key of sufficient length
$ ls -l sealed.box
-rw-r--r--+ 1 user  staff  47 Jun 18 12:24 insecurely_sealed.box
```

### Prompting for the key (WIP)
Use option `-a` to be asked for a key.

```
$ echo foobar | seal_box -a > sealed.box
Please enter key: 
```

## `open_box`
Reads ciphertext (including MAC and nonce) from STDIN. Writes plaintext to STDOUT. The
key can be given in the same ways as for `seal_box`. For example directly on the command line:

```
$ open_box -k secret.key < sealed.box
foobar
```

In case the box has been tampered with, verification of the MAC will and the
program will exit with a message on STDERR. Example:

```
$ echo foobar | seal_box -k secret.key > sealed.box
$ ls -l sealed.box secret.key
-rw-r--r--+ 1 user  staff  47 Jun 18 12:27 sealed.box
-r--------+ 1 user  staff  47 Jun 18 12:27 secret.key
$ echo "baz" >> sealed.box
$ ls -l sealed.box
-rw-r--r--+ 1 user  staff  51 Jun 18 12:27 sealed.box
$ open_box -k secret.key < sealed.box
Ciphertext couldn't be verified. It has been tampered with or you're using the wrong key.
```

## Internals
The current implementation never creates any (temporary) files, no matter how big the input is.

The cryptographic primitives used are XSalsa20 and Poly1305.

XSalsa20 (with its 24 byte nonces) is a good choice because it allows one to
safely use randomly generated nonces. Of course, the full 20-rounds version of
XSalsa20 is used.

Poly1305 will ensure the integrity of your data. Never use encryption without
authentication to verify the integrity of the encrypted data. If you don't care
if someone tampers with your data, you might as well just send plaintext.
