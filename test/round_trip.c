#include "lock_box.h"
#include "open_box.h"

#include <check.h>
#include <stdlib.h>
#include <stdio.h>

START_TEST(test_round_trip)

  if (sodium_init() == -1) {
    fprintf(stderr, "unable to initialize libsodium\n");
    exit(EXIT_FAILURE);
  }

  //char *ct_filename = mktemp("
  FILE *ct = tmpfile();

  randombytes_buf(key, KEY_BYTES);

  FILE *input = fopen("lorem.txt")


END_TEST


static Suite *crypto_box_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Crypto Box");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_round_trip);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = crypto_box_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
