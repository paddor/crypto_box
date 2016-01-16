#include "config.h"
#include "key.h"
#include "encryption.h"
#include "decryption.h"
#include "util.h"

#include <err.h>
#include <sysexits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <check.h>
#include <sodium.h>

static char *input_file_name;
static int round_trip(_Bool hex_wanted)
{
  crypto_box_init();

  int fd_ct, fd_pt2;
  FILE *pt1, *ct, *pt2;
  char template[] = "/tmp/round_trip.XXXXXX";

  /* generate names and open temporary files */
  char *fname_pt2 = malloc(sizeof template);
  if (fname_pt2 == NULL)
    errx(EX_OSERR, "Couldn't allocate fname_pt2");
  char *fname_ct = malloc(sizeof template);
  if (fname_ct == NULL)
    errx(EX_OSERR, "Couldn't allocate fname_ct");

  memcpy(fname_ct, template, sizeof template);
  memcpy(fname_pt2, template, sizeof template);
  fd_ct = mkstemp(fname_ct);
  fd_pt2 = mkstemp(fname_pt2);
  if (fd_ct == -1 || fd_pt2 == -1)
    err(EX_CANTCREAT, "Couldn't create temporary file");

  fprintf(stderr, "ciphertext file: %s\n", fname_ct);
  fprintf(stderr, "plaintext (2) file: %s\n", fname_pt2);

  /* open/associate file descriptors with file streams (FILE*) */
  pt1 = fopen(input_file_name, "r");
  if (pt1 == NULL) err(EX_NOINPUT, "Couldn't read input file");
  ct = fdopen(fd_ct, "r+");
  if (ct == NULL) err(EX_IOERR, "Couldn't reopen ciphertext file for r+");
  pt2 = fdopen(fd_pt2, "r+");
  if (pt2 == NULL) err(EX_IOERR, "Couldn't reopen second plaintext file for r+");

  /* generate random key */
  uint8_t *key;
  key_malloc(&key);
  randombytes_buf(key, crypto_stream_xsalsa20_KEYBYTES);

  /* encrypt -> CT file */
  lock_box(pt1, ct, key, hex_wanted);
  fprintf(stderr, "encrypted data to: %s\n", fname_ct);

  /* decrypt -> PT2 file */
  rewind(ct);
  open_box(ct, pt2, key, hex_wanted);
  fprintf(stderr, "decrypted data to: %s\n", fname_pt2);

  /* hash PT1 and PT2 file contents */
  unsigned char hash_pt1[crypto_generichash_BYTES];
  unsigned char hash_pt2[crypto_generichash_BYTES];
  crypto_generichash_state state_pt1;
  crypto_generichash_state state_pt2;
  crypto_generichash_init(&state_pt1, NULL, 0, sizeof hash_pt1);
  crypto_generichash_init(&state_pt2, NULL, 0, sizeof hash_pt2);
  size_t nread;
  unsigned char *buf = malloc(CHUNK_CT_BYTES); /* size doesn't really matter */
  if (buf == NULL)
    errx(EX_OSERR, "Couldn't allocate buffer");
  rewind(pt1);
  while(!feof(pt1)) {
    nread = fread(buf, 1, CHUNK_CT_BYTES, pt1);
    if (nread < CHUNK_CT_BYTES && ferror(pt1))
      err(EX_IOERR, "Couldn't read from first plaintext file");
    crypto_generichash_update(&state_pt1, buf, nread);
  }
  rewind(pt2);
  while(!feof(pt2)) {
    nread = fread(buf, 1, CHUNK_CT_BYTES, pt2);
    if (nread < CHUNK_CT_BYTES && ferror(pt2))
      err(EX_IOERR, "Couldn't read from second plaintext file");
    crypto_generichash_update(&state_pt2, buf, nread);
  }
  crypto_generichash_final(&state_pt1, hash_pt1, sizeof hash_pt1);
  crypto_generichash_final(&state_pt2, hash_pt2, sizeof hash_pt2);

  /* compare PT1 and PT2 hashes */
  ck_assert_int_eq(0, memcmp(hash_pt1, hash_pt2,
        crypto_generichash_BYTES));

  sodium_free(key);
  return 0;
}

START_TEST(test_binary_round_trip)
  _Bool hex_wanted = false; /* binary */
  ck_assert_int_eq(0, round_trip(hex_wanted));
END_TEST

START_TEST(test_hex_round_trip)
  _Bool hex_wanted = true; /* hex */
  ck_assert_int_eq(0, round_trip(hex_wanted));
END_TEST


static Suite *crypto_box_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Crypto Box");

    /* Core test case */
    tc_core = tcase_create("Round Trip");

    tcase_add_test(tc_core, test_binary_round_trip);
    tcase_add_test(tc_core, test_hex_round_trip);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(int argc, char *argv[])
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    if (argc == 2) {
      input_file_name = argv[1];
    } else {
      errx(EX_USAGE, "Usage: %s <input_file.txt>", argv[0]);
    }

    s = crypto_box_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
// vim: et:ts=2:sw=2
