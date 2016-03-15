#include <check.h>
#include <stdlib.h>

#include "aid/crypto/asymkeys.h"
#include "aid/core/utils.h"
 
START_TEST(test_asymkeys_generate)
{
    aid_asymkeys_private_t priv;
    aid_asymkeys_public_t pub;
    int res;

    for(unsigned int i = 1; i <= AID_ASYMKEYS_NUM; ++i) {
        res = aid_asymkeys_generate(
            (aid_asymkeys_t) i,
            &aid_utils_rand,
            NULL,
            &priv,
            &pub);

        ck_assert_msg(priv.type == pub.type, "Types of generated keypair do not match.\n");

        aid_asymkeys_cleanup_priv(&priv);
        aid_asymkeys_cleanup_pub(&pub);

        ck_assert_msg(res == 0, "Failed to generate keys of type %s.\n", aid_asymkeys_index(i)->name);

    }

}
END_TEST

START_TEST(test_asymkeys_public)
{
    aid_asymkeys_private_t priv;
    aid_asymkeys_public_t pub1, pub2;
    int res;

    for(unsigned int i = 1; i <= AID_ASYMKEYS_NUM; ++i) {
        aid_asymkeys_generate(
            (aid_asymkeys_t) i,
            &aid_utils_rand,
            NULL,
            &priv,
            &pub1);

        res = aid_asymkeys_public(
            (aid_asymkeys_private_t const *) &priv,
            &pub2);

        ck_assert_msg(res == 0, "Failed to calculate public key of type %s.\n", aid_asymkeys_index(i)->name);
        ck_assert_msg(pub1.type == pub2.type, "Types of the calculated public key is incorrect.\n");
        res = memcmp(pub1.key, pub2.key, aid_asymkeys_index(i)->pub_size);
        ck_assert_msg(res == 0, "Incorrectly calculated private key of type %s. \n", aid_asymkeys_index(i)->name);

        aid_asymkeys_cleanup_priv(&priv);
        aid_asymkeys_cleanup_pub(&pub1);
        aid_asymkeys_cleanup_pub(&pub2);
    }

}
END_TEST

 
Suite *
asymkeys_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Asymmetric Keys");

    /* Main test case */
    tc_core = tcase_create("Main");

    tcase_add_test(tc_core, test_asymkeys_generate);
    tcase_add_test(tc_core, test_asymkeys_public);
    suite_add_tcase(s, tc_core);

    return s;
}


int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = asymkeys_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

