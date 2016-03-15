#include <check.h>
#include <stdlib.h>

#include "aid/crypto/asymkeys.h"
#include "aid/crypto/asymsign.h"
#include "aid/core/utils.h"

START_TEST(test_asymsign_sign_verify)
{
    aid_asymkeys_private_t priv;
    aid_asymkeys_public_t pub;
    aid_asymkeys_t keytype;
    char const *data = "this is some random data to be tested. random data test test test, it's not very random at all.";
    int res;
    size_t sigsize, dsize;
    unsigned char *sigbuf;

    dsize = strlen(data);

    for(unsigned int i = 1; i <= AID_ASYMSIGN_NUM; ++i) {
        keytype = aid_asymsign_index(i)->key_type;
        res = aid_asymkeys_generate(
            keytype,
            &aid_utils_rand,
            NULL,
            &priv,
            &pub);

        ck_assert_msg(res == 0, "Failed to generate keys of type %s.\n", aid_asymkeys_index(keytype)->name);

        sigsize = aid_asymsign_index(i)->sig_size;
        sigbuf = malloc(sigsize);
        ck_assert_msg(sigbuf != NULL, "Failed to allocate memory for signature buffer.\n");

        res = aid_asymsign_sign(
            (aid_asymsign_t) i,
            (unsigned char const *)data,
            dsize,
            sigbuf,
            sigsize,
            &priv);

        ck_assert_msg(res == 0, "Failed to sign data with algorithm %s.\n", aid_asymsign_index(i)->name);

        res = aid_asymsign_verify(
            (aid_asymsign_t) i,
            (unsigned char const *)data,
            dsize,
            (unsigned char const *)sigbuf,
            sigsize,
            &pub);

        ck_assert_msg(res == 0, "Failed to verify signature with algorithm %s.\n", aid_asymsign_index(i)->name);

        memcpy(sigbuf, (unsigned char const *) data, (dsize > sigsize ? sigsize : dsize));

        res = aid_asymsign_verify(
            (aid_asymsign_t) i,
            (unsigned char const *)data,
            dsize,
            (unsigned char const *)sigbuf,
            sigsize,
            &pub);

        ck_assert_msg(res == 1, "Failed to detect invalid signature with algorithm %s.\n", aid_asymsign_index(i)->name);

        free(sigbuf);
        aim_asymkeys_cleanup_priv(&priv);
        aim_asymkeys_cleanup_pub(&pub);
    }

}
END_TEST


Suite *
asymsign_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Asymmetric Signing");

    tc_core = tcase_create("Main");

    tcase_add_test(tc_core, test_asymsign_sign_verify);
    suite_add_tcase(s, tc_core);

    return s;
}


int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = asymsign_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

