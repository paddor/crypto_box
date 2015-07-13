#include "crypto_box.h"
#include "key.h"
#include "encryption.h"
#include "decryption.h"

#include <check.h>
#include <stdlib.h>
#include <stdio.h>

static char *input_file_name;
static int round_trip(void)
{
  crypto_box_init();

  int fd_ct, fd_pt2;
  FILE *pt1, *ct, *pt2;
  char template[] = "/tmp/round_trip.XXXXXX";

  /* generate names and open temporary files */
  char *fname_pt2 = malloc(sizeof template);
  char *fname_ct = malloc(sizeof template);
  if (fname_ct == NULL || fname_pt2 == NULL) exit(EXIT_FAILURE);
  memcpy(fname_ct, template, sizeof template);
  memcpy(fname_pt2, template, sizeof template);
  fd_ct = mkstemp(fname_ct);
  fd_pt2 = mkstemp(fname_pt2);
  if (fd_ct == -1 || fd_pt2 == -1) {
    perror("Couldn't create temporary file");
    exit(EXIT_FAILURE);
  }
  fprintf(stderr, "ciphertext file: %s\n", fname_ct);
  fprintf(stderr, "plaintext (2) file: %s\n", fname_pt2);

  /* open/associate file descriptors with file streams (FILE*) */
  pt1 = fopen(input_file_name, "r");
  ct = fdopen(fd_ct, "r+");
  pt2 = fdopen(fd_pt2, "r+");

  if (pt1 == NULL || ct == NULL || pt2 == NULL) exit(EXIT_FAILURE);

  /* generate random key */
  uint8_t *key;
  if (key_malloc(&key) == -1) goto abort;
  randombytes_buf(key, crypto_stream_xsalsa20_KEYBYTES);

  /* encrypt -> CT file */
  lock_box(pt1, ct, key);

  /* decrypt -> PT2 file */
  rewind(ct);
  open_box(ct, pt2, key);

  /* hash PT1 and PT2 file contents */
  unsigned char hash_pt1[crypto_generichash_BYTES];
  unsigned char hash_pt2[crypto_generichash_BYTES];
  crypto_generichash_state state_pt1;
  crypto_generichash_state state_pt2;
  crypto_generichash_init(&state_pt1, NULL, 0, sizeof hash_pt1);
  crypto_generichash_init(&state_pt2, NULL, 0, sizeof hash_pt2);
  size_t nread;
  unsigned char *buf = malloc(CHUNK_CT_BYTES); /* size doesn't really matter */
  if (buf == NULL) exit(EXIT_FAILURE);
  rewind(pt1);
  while(!feof(pt1)) {
    nread = fread(buf, 1, CHUNK_CT_BYTES, pt1);
    if (nread < CHUNK_CT_BYTES && ferror(pt1)) exit(EXIT_FAILURE);
    crypto_generichash_update(&state_pt1, buf, nread);
  }
  rewind(pt2);
  while(!feof(pt2)) {
    nread = fread(buf, 1, CHUNK_CT_BYTES, pt2);
    if (nread < CHUNK_CT_BYTES && ferror(pt2)) exit(EXIT_FAILURE);
    crypto_generichash_update(&state_pt2, buf, nread);
  }
  crypto_generichash_final(&state_pt1, hash_pt1, sizeof hash_pt1);
  crypto_generichash_final(&state_pt2, hash_pt2, sizeof hash_pt2);

  /* compare PT1 and PT2 hashes */
  ck_assert_int_eq(0, sodium_memcmp(hash_pt1, hash_pt2,
        crypto_generichash_BYTES));

  sodium_free(key);
  return 0;

abort:
  sodium_free(key);
  return -1;
}

START_TEST(test_binary_round_trip)
  arguments.ct_format = BIN;
  ck_assert_int_eq(0, round_trip());
END_TEST

START_TEST(test_hex_round_trip)
  arguments.ct_format = HEX;
  ck_assert_int_eq(0, round_trip());
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
      fprintf(stderr, "Usage: %s <input_file.txt>\n", argv[0]);
      return EXIT_FAILURE;
    }

    s = crypto_box_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
// vim: et:ts=2:sw=2
