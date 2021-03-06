#include "test_crypto.h"

#include "aid/crypto/asymkeys.h"
#include "aid/crypto/kdf.h"
#include "aid/crypto/symmkeys.h"
#include "aid/core/utils.h"

START_TEST(test_kdf_compute)
{
    aid_asymkeys_private_t priv1;
    aid_asymkeys_public_t pub1;
    aid_asymkeys_private_t priv2;
    aid_asymkeys_public_t pub2;
    aid_asymkeys_t asym_type;
    aid_kdf_index_t const *index;
    aid_symmkeys_key_t key1, key2;
    char *a = "abc";
    int res;
    size_t symmsize;

    for(unsigned int i = 1; i <= AID_KDF_NUM; ++i) {
        index = aid_kdf_index(i);
        asym_type = index->input_type;
        symmsize = aid_symmkeys_index(index->key_type)->key_size;

        res = aid_asymkeys_generate(
            asym_type,
            &aid_utils_rand,
            (void *) a,
            &priv1,
            &pub1);

        ck_assert_msg(res == 0, "Failed to generate asymmetric key pair.\n");

        res = aid_asymkeys_generate(
            asym_type,
            &aid_utils_rand,
            (void *) a,
            &priv2,
            &pub2);

        ck_assert_msg(res == 0, "Failed to generate asymmetric key pair.\n");

        res = aid_kdf_compute(
            (aid_kdf_t) i,
            (aid_asymkeys_private_t const *)&priv1,
            (aid_asymkeys_public_t const *)&pub2,
            &key1);

        ck_assert_msg(res == 0, "Failed to compute symmetric key with KDF algorithm %s.\n", index->name);

        res = aid_kdf_compute(
            (aid_kdf_t) i,
            (aid_asymkeys_private_t const *)&priv2,
            (aid_asymkeys_public_t const *)&pub1,
            &key2);

        ck_assert_msg(res == 0, "Failed to compute symmetric key with KDF algorithm %s.\n", index->name);
        ck_assert_msg((key1.type == key2.type) && (key1.type == index->key_type),
                "Failed to compute keys of correct types with KDF algorithm %s.\n", index->name);
        res = memcmp(key1.key, key2.key, symmsize);
        ck_assert_msg(res == 0, "Different keys were produced using KDF algorithm %s.\n", index->name);

        aid_asymkeys_cleanup_pub(&pub1);
        aid_asymkeys_cleanup_pub(&pub2);
        aid_asymkeys_cleanup_priv(&priv1);
        aid_asymkeys_cleanup_priv(&priv2);
        aid_symmkeys_cleanup(&key1);
        aid_symmkeys_cleanup(&key2);
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

