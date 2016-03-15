#include <check.h>
#include <stdlib.h>

#include "aid/crypto/symmkeys.h"
#include "aid/crypto/symmcrypt.h"
#include "aid/core/utils.h"

START_TEST(test_symmcrypt_encrypt_decrypt)
{
    aid_symmcrypt_index_t const *index;
    aid_symmkeys_key_t key;
    aid_symmkeys_t keytype;
    char const *data = "Look at all this new data that we will use to test encryption and encryption.";
    int res;
    size_t dsize, csize, psize, ivsize;
    unsigned char *cipher, *plain, *iv;

    dsize = strlen(data);

    for (unsigned int i = 1; i <= AID_SYMMCRYPT_NUM; ++i) {
        index = aid_symmcrypt_index(i);
        keytype = index->key_type;
        res = aid_symmkeys_generate(
            keytype,
            &aid_utils_rand,
            NULL,
            &key);

        ck_assert_msg(res == 0, "Failed to generate keys of time %s.\n", aid_symmkeys_index(keytype)->name);

        ivsize = index->iv_size;
        iv = malloc(ivsize);
        ck_assert_msg(iv != NULL, "Failed to allocate memory for initialization vector buffer.\n");

        res = aid_utils_rand(
            NULL,
            iv,
            ivsize);

        ck_assert_msg(res == 0, "Failed to generate random data for initialization vector.\n");


        csize = index->cipherlen(dsize);
        cipher = malloc(csize);
        ck_assert_msg(cipher != NULL, "Failed to allocate memory for cipher buffer.\n");

        res = aid_symmcrypt_encrypt(
            (aid_symmcrypt_t) i,
            (unsigned char const *)data,
            dsize,
            cipher,
            csize,
            iv,
            ivsize,
            &key);

        ck_assert_msg(res == 0, "Failed to encrypt data with algorithm %s.\n", index->name);

        psize = index->plainlen(csize);
        plain = malloc(psize);
        ck_assert_msg(plain != NULL, "Failed to allocate memory for plaintext buffer.\n");

        res = aid_symmcrypt_decrypt(
            (aid_symmcrypt_t) i,
            (unsigned char const *)cipher,
            csize,
            plain,
            psize,
            iv,
            ivsize,
            &key);

        ck_assert_msg(res == 0, "Failed to decrypt data with algorithm %s.\n", index->name);

        res = memcmp(data, plain, (dsize > psize ? psize : dsize));
        ck_assert_msg(res == 0, "Encryption and decryption test failed for algorithm %s.\n", index->name);

        free(iv);
        free(cipher);
        free(plain);
        aid_symmkeys_cleanup(&key);
    }

}
END_TEST


Suite *
symmcrypt_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Symmetric Encryption");

    tc_core = tcase_create("Main");

    tcase_add_test(tc_core, test_symmcrypt_encrypt_decrypt);
    suite_add_tcase(s, tc_core);

    return s;
}


int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = symmcrypt_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


