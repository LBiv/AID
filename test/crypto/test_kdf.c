#include <check.h>
#include <stdlib.h>

#include "aid/crypto/asymkeys.h"
#include "aid/crypto/KDF.h"
#include "aid/crypto/symmkeys.h"
#include "aid/core/utils.h"

START_TEST(test_KDF_compute)
{
    aid_asymkeys_private_t priv1;
    aid_asymkeys_public_t pub1;
    aid_asymkeys_private_t priv2;
    aid_asymkeys_public_t pub2;
    aid_asymkeys_t asym_type;
    aid_KDF_index_t const *index;
    aid_symmkeys_key_t key1, key2;
    int res;
    size_t symmsize;

    for(unsigned int = 1; i <= AID_KDF_NUM; ++i) {
        index = aid_KDF_index(i);
        asym_type = index->input_type;
        symmsize = aid_symmkey_index(index->key_type)->key_size;

        res = aid_asymkeys_generate(
            asym_type,
            &aid_util_rand,
            NULL,
            &priv1,
            &pub1);

        ck_assert_msg(res == 0, "Failed to generate asymmetric key pair.\n");

        res = aid_asymkeys_generate(
            asym_type,
            &aid_util_rand,
            NULL,
            &priv2,
            &pub2);

        ck_assert_msg(res == 0, "Failed to generate asymmetric key pair.\n");

        res = aid_KDF_compute(
            (aid_KDF_t) i,
            (aid_asymkeys_private_t const *)priv1,
            (aid_asymkeys_public_t const *)pub2,
            key1);

        ck_assert_msg(res == 0, "Failed to compute symmetric key with KDF algorithm %s.\n", index->name);

        res = aid_KDF_compute(
            (aid_KDF_t) i,
            (aid_asymkeys_private_t const *)priv2,
            (aid_asymkeys_public_t const *)pub1,
            key2);

        ck_assert_msg(res == 0, "Failed to compute symmetric key with KDF algorithm %s.\n", index->name);
        ck_assert_msg(key1->type == key2->type == index->key_type, "Failed to compute keys of correct types with KDF algorithm %s.\n", index->name);
        memcmp(key1->key, key2->key, symmsize);
        ck_assert_msg(res == 0, "Different keys were produced using KDF algorithm %s.\n", index->name);

        aid_asymkeys_cleanup_pub(pub1);
        aid_asymkeys_cleanup_pub(pub2);
        aid_asymkeys_cleanup_priv(priv1);
        aid_asymkeys_cleanup_priv(priv2);
        aid_symmkeys_cleanup(key1);
        aid_symmkeys_cleanup(key2);
    }

}
END_TEST


Suite *
kdf_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Key Derivation Functions");

    tc_core = tcase_create("Main");

    tcase_add_test(tc_core, test_kdf_compute);
    suite_add_tcase(s, tc_core);

    return s;
}


int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = kdf_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

