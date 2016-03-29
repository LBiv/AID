#include "test_crypto.h"

#include "aid/crypto/asymkeys.h"
#include "aid/core/utils.h"


START_TEST(test_asymkeys_generate)
{
    aid_asymkeys_private_t priv;
    aid_asymkeys_public_t pub;
    char *a = "abc";
    int res;

    for(unsigned int i = 1; i <= AID_ASYMKEYS_NUM; ++i) {
        res = aid_asymkeys_generate(
            (aid_asymkeys_t) i,
            &aid_utils_rand,
            (void *) a,
            &priv,
            &pub);

        ck_assert_msg(res == 0, "Failed to generate keys of type %s.\n", aid_asymkeys_index(i)->name);
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
    char *a = "abc";
    int res;

    for(unsigned int i = 1; i <= AID_ASYMKEYS_NUM; ++i) {
        res = aid_asymkeys_generate(
            (aid_asymkeys_t) i,
            &aid_utils_rand,
            (void *) a,
            &priv,
            &pub1);

        ck_assert_msg(res == 0, "Failed to generate keypair of type %s.\n", aid_asymkeys_index(i)->name);

        res = aid_asymkeys_public(
            (aid_asymkeys_private_t const *) &priv,
            &pub2);

        ck_assert_msg(res == 0, "Failed to calculate public key of type %s.\n", aid_asymkeys_index(i)->name);
        ck_assert_msg(pub1.type == pub2.type, "Types of the calculated public key is incorrect.\n");
        res = memcmp(pub1.key, pub2.key, aid_asymkeys_index(i)->pub_size);
        ck_assert_msg(res == 0, "Incorrectly calculated public key of type %s.\n", aid_asymkeys_index(i)->name);

        aid_asymkeys_cleanup_priv(&priv);
        aid_asymkeys_cleanup_pub(&pub1);
        aid_asymkeys_cleanup_pub(&pub2);
    }

}
END_TEST


START_TEST(test_asymkeys_binary_priv)
{
    aid_asymkeys_index_t const *index;
    aid_asymkeys_private_t priv1, priv2;
    aid_asymkeys_public_t pub;
    char *a = "abc";
    int res;
    size_t buf_size;
    unsigned char *buf1, *buf2;

    for(unsigned int i = 1; i <= AID_ASYMKEYS_NUM; ++i) {

        index = aid_asymkeys_index(i);
        ck_assert_msg(index != NULL, "Invalid private key type specified for testing.\n");

        res = aid_asymkeys_generate(
            (aid_asymkeys_t) i,
            &aid_utils_rand,
            (void *) a,
            &priv1,
            &pub);

        ck_assert_msg(res == 0, "Failed to generate keys of type %s.\n", index->name);
        ck_assert_msg(priv1.type == i, "Generated key of invalid type.\n");

        buf_size = index->priv_size + 1;

        buf1 = malloc(buf_size);
        buf2 = malloc(buf_size);
        ck_assert_msg((buf1 != NULL) && (buf2 != NULL), "Failed to allocate memory for serialized private key of type %s.\n",
            index->name);

        res = aid_asymkeys_to_binary_priv(
            (aid_asymkeys_private_t const *) &priv1,
            buf1,
            buf_size);

        ck_assert_msg(res == 0, "Failed to convert private key of type %s to binary.\n", index->name);

        res = aid_asymkeys_from_binary_priv(
            (unsigned char const *) buf1,
            buf_size,
            &priv2);

        ck_assert_msg(res == 0, "Failed to parse private key of type %s from binary.\n", index->name);
        ck_assert_msg(priv1.type == priv2.type, "Private key of type %s was corrupted by serialization and deserialization.\n",
                index->name);

        res = aid_asymkeys_to_binary_priv(
            (aid_asymkeys_private_t const *) &priv2,
            buf2,
            buf_size);

        ck_assert_msg(res == 0, "Failed to parse private key of type %s from binary.\n", index->name);
        res = memcmp(buf1, buf2, buf_size);
        ck_assert_msg(res == 0, "Private key of type %s was corrupted by serialization and deserialization.\n",
            index->name);

        free(buf1);
        free(buf2);
        aid_asymkeys_cleanup_priv(&priv1);
        aid_asymkeys_cleanup_priv(&priv2);
        aid_asymkeys_cleanup_pub(&pub);
    }

}
END_TEST

 
START_TEST(test_asymkeys_binary_pub)
{
    aid_asymkeys_index_t const *index;
    aid_asymkeys_private_t priv;
    aid_asymkeys_public_t pub1, pub2;
    char *a = "abc";
    int res;
    size_t buf_size;
    unsigned char *buf1, *buf2;

    for(unsigned int i = 1; i <= AID_ASYMKEYS_NUM; ++i) {

        index = aid_asymkeys_index(i);
        ck_assert_msg(index != NULL, "Invalid private key type specified for testing.\n");

        res = aid_asymkeys_generate(
            (aid_asymkeys_t) i,
            &aid_utils_rand,
            (void *) a,
            &priv,
            &pub1);

        ck_assert_msg(res == 0, "Failed to generate keys of type %s.\n", index->name);
        ck_assert_msg(pub1.type == i, "Generated key of invalid type.\n");

        buf_size = index->pub_size + 1;

        buf1 = malloc(buf_size);
        buf2 = malloc(buf_size);
        ck_assert_msg((buf1 != NULL) && (buf2 != NULL), "Failed to allocate memory for serialized public key of type %s.\n",
            index->name);

        res = aid_asymkeys_to_binary_pub(
            (aid_asymkeys_public_t const *) &pub1,
            buf1,
            buf_size);

        ck_assert_msg(res == 0, "Failed to convert public key of type %s to binary.\n", index->name);

        res = aid_asymkeys_from_binary_pub(
            (unsigned char const *) buf1,
            buf_size,
            &pub2);

        ck_assert_msg(res == 0, "Failed to parse public key of type %s from binary.\n", index->name);
        ck_assert_msg(pub1.type == pub2.type, "Public key of type %s was corrupted by serialization and deserialization.\n",
                index->name);

        res = aid_asymkeys_to_binary_pub(
            (aid_asymkeys_public_t const *) &pub2,
            buf2,
            buf_size);

        ck_assert_msg(res == 0, "Failed to parse public key of type %s from binary.\n", index->name);
        res = memcmp(buf1, buf2, buf_size);
        ck_assert_msg(res == 0, "Public key of type %s was corrupted by serialization and deserialization.\n",
            index->name);

        free(buf1);
        free(buf2);
        aid_asymkeys_cleanup_pub(&pub1);
        aid_asymkeys_cleanup_pub(&pub2);
        aid_asymkeys_cleanup_priv(&priv);
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
    tcase_add_test(tc_core, test_asymkeys_binary_priv);
    tcase_add_test(tc_core, test_asymkeys_binary_pub);
    suite_add_tcase(s, tc_core);

    return s;
}

