#include <check.h>
#include <stdlib.h>

#include "aid/crypto/hash.h"

START_TEST(test_hash_digest_verify)
{
    char const *data = "This is some data to test the hashing functions. Hash hash hash data data data function function function";
    int res;
    size_t dsize, hashsize;
    unsigned char *hashbuf;

    dsize = strlen(data);

    for(unsigned int i = 1; i <= AID_HASH_NUM; ++i) {
        hashsize = aid_hash_index(i)->hash_size;
        hashbuf = malloc(hashsize);
        ck_assert_msg(hashbuf != NULL, "Failed to allocate memory for hash buffer.\n");

        res = aid_hash_digest(
            (aid_hash_t) i,
            (unsigned char const *) data,
            dsize,
            hashbuf,
            hashsize);

        ck_assert_msg(res == 0, "Failed to hash data with algorithm %s.\n", aid_hash_index(i)->name);

        res = aid_hash_verify(
            (aid_hash_t) i,
            (unsigned char const *) data,
            dsize,
            (unsigned char const *) hashbuf,
            hashsize);

        ck_assert_msg(res == 0, "Failed to verify result of hash algorithm %s.\n", aid_hash_index(i)->name);

        memcpy(hashbuf, (unsigned char const *) data, (dsize > hashsize ? hashsize : dsize));

        res = aid_hash_verify(
            (aid_hash_t) i,
            (unsigned char const *) data,
            dsize,
            (unsigned char const *)hashbuf,
            hashsize);

        ck_assert_msg(res == 1, "Failed to detect invalid hash with algorithm %s.\n", aid_hash_index(i)->name);

        free(hashbuf);
    }

}
END_TEST

Suite *
hash_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Cryptographic Hashing");

    tc_core = tcase_create("Main");

    tcase_add_test(tc_core, test_hash_digest_verify);
    suite_add_tcase(s, tc_core);

    return s;
}


int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = hash_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

