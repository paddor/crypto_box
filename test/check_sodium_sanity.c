#include <stdlib.h>
#include <check.h>
#include <sodium.h>
#include <stdio.h>

START_TEST(test_sodium_sanity)
{
  ck_assert_msg(sodium_init() == 0,
    "unable to initialize libsodium");
}
END_TEST


static Suite *crypto_box_suite(void)
{
    Suite *s;
    TCase *tc_libsodium;

    s = suite_create("Sanity Suite");

    /* Sodium test case */
    tc_libsodium = tcase_create("libsodum");

    tcase_add_test(tc_libsodium, test_sodium_sanity);

    suite_add_tcase(s, tc_libsodium);

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
