#include "test_crypto.h"

#include "aid/crypto/symmkeys.h"
#include "aid/core/utils.h"

START_TEST(test_symmkeys_binary)
{
    aid_symmkeys_index_t const *index;
    aid_symmkeys_key_t key1, key2;
    char *a = "abc";
    int res;
    size_t buf_size;
    unsigned char *buf1, *buf2;

    for(unsigned int i = 1; i <= AID_SYMMKEYS_NUM; ++i) {

        index = aid_symmkeys_index(i);
        ck_assert_msg(index != NULL, "Invalid symmetric key type specified for testing.\n");

        res = aid_symmkeys_generate(
            (aid_symmkeys_t) i,
            &aid_utils_rand,
            (void *) a,
            &key1);

        ck_assert_msg(res == 0, "Failed to generate keys of type %s.\n", index->name);
        ck_assert_msg(key1.type == i, "Generated key of invalid type.\n");

        buf_size = index->key_size + 1;

        buf1 = malloc(buf_size);
        buf2 = malloc(buf_size);
        ck_assert_msg((buf1 != NULL) && (buf2 != NULL), "Failed to allocate memory for serialized symmetric key of type %s.\n",
            index->name);

        res = aid_symmkeys_to_binary(
            (aid_symmkeys_key_t const *) &key1,
            buf1,
            buf_size);

        ck_assert_msg(res == 0, "Failed to convert symmetric key of type %s to binary.\n", index->name);

        res = aid_symmkeys_from_binary(
            (unsigned char const *) buf1,
            buf_size,
            &key2);

        ck_assert_msg(res == 0, "Failed to parse symmetric key of type %s from binary.\n", index->name);
        ck_assert_msg(key1.type == key2.type, "Symmetric key of type %s was corrupted by serialization and deserialization.\n",
                index->name);

        res = aid_symmkeys_to_binary(
            (aid_symmkeys_key_t const *) &key2,
            buf2,
            buf_size);

        ck_assert_msg(res == 0, "Failed to parse symmetric key of type %s from binary.\n", index->name);
        res = memcmp(buf1, buf2, buf_size);
        ck_assert_msg(res == 0, "Symmetric key of type %s was corrupted by serialization and deserialization.\n",
            index->name);

        free(buf1);
        free(buf2);
        aid_symmkeys_cleanup(&key1);
        aid_symmkeys_cleanup(&key2);
    }

}
END_TEST


Suite *
symmkeys_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Symmetric Keys");

    tc_core = tcase_create("Main");

    tcase_add_test(tc_core, test_symmkeys_binary);
    suite_add_tcase(s, tc_core);

    return s;
}
