# crypto_box
This gives you two utilities: `seal_box` and `open_box`.

# `seal_box`
Reads plaintext on STDIN. Writes ciphertext (and MAC and nonce) on STDOUT.
By default, it uses a randomly generated key.

```
$ echo foobar |./seal_box > sealed.box
Your key: 4a5c4119c24b0db47bb4b4d8383c716ea390f04553f8877d0c94099e1ac12eb6
$ ls -l sealed.box
-rw-r--r--+ 1 user  staff  47 Jun 18 12:20 sealed.box
$ 
```

The output file in this case is 7+16+24=47 bytes long, for ciphertext, MAC and nonce, respectively.

You can specify a key on the command line, in hex. Make sure your command won't get logged!
Colons (`:`) and whitespace characters (` `) in the key are ignored. So the
following two examples are equivalent:

```
$ echo foobar |./seal_box abba0ff887ca6064622b30a47a2aa9980faa1f544b24a9991b14e948d7331728 > sealed.box
$ ls -l sealed.box
-rw-r--r--+ 1 user  staff  47 Jun 18 12:22 sealed.box
$ 
```

```
$ echo foobar |./seal_box ab:ba:0f:f8:87:ca:60:64:62:2b:30:a4:7a:2a:a9:98:0f:aa:1f:54:4b:24:a9:99:1b:14:e9:48:d7:33:17:28 > sealed.box
$ ls -l sealed.box
-rw-r--r--+ 1 user  staff  47 Jun 18 12:22 sealed.box
$ 
```

A key shorter than 32 byte (which would be at least 64 ASCII hex characters)
will be repeated to make up a complete 32 byte key. This is not recommended.

```
$ echo foobar |./seal_box 6ea390f04553 > insecurely_sealed.box
WARNING: reuising key material to make up a key of sufficient length
$ ls -l sealed.box
-rw-r--r--+ 1 user  staff  47 Jun 18 12:24 insecurely_sealed.box
$ 
```

Use option `-a` to make it ask for a key.


# `open_box`
Reads ciphertext (and MAC and nonce) on STDIN. Writes plaintext on STDOUT. The
key can be given the same way as for `seal_box`. For example directly on the command line:

```
$ ./open_box 4a5c4119c24b0db47bb4b4d8383c716ea390f04553f8877d0c94099e1ac12eb6 < sealed.box
foobar
$ 
```

Or using a shorter key:

```
$ ./open_box 6ea390f04553 < insecurely_sealed.box
foobar
$ 
```

In case the box has been tampered with, verification of the MAC will and the
program will exit with a message on STDERR. Example:

```
$ echo foobar |./seal_box > sealed.box
Your key: c4eb8509d97e2d955339bfe4eb91078605099818d1334a09602fae22d76cbd88
$ ls -l sealed.box
-rw-r--r--+ 1 user  staff  47 Jun 18 12:27 sealed.box
$ echo "baz" >> sealed.box
$ ls -l sealed.box
-rw-r--r--+ 1 user  staff  51 Jun 18 12:27 sealed.box
$ ./open_box c4eb8509d97e2d955339bfe4eb91078605099818d1334a09602fae22d76cbd88 < sealed.box
Ciphertext couldn't be verified. It has been tampered with or you're using the wrong key.
$ 
```

Using the option `-a` to make it ask for the key is also supported.

# Cryptographic Primitives
XSalsa20 and Poly1305 are used.
