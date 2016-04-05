#include "test_common.h"

#include <string.h>

#include "aid/common/crypto.h"

START_TEST(test_common_crypto_hash)
{
    int res = 0;
    size_t dsize = 313, bufsize;
    unsigned char data[313];
    unsigned char *hashbuf;

    res = crypto_rng_init();
    cK_assert_msg(res == 0, "Failed to initialize random number generator.\n");

    bufsize = crypto_hash_size();
    hashbuf = malloc(bufsize);
    ck_assert_msg(hashbuf != NULL, "Failed to allocate memory for cryptographic hash.\n");

    res = crypto_rand(
        rng_ctx,
        data,
        dsize);

    ck_assert_msg(res == 0, "Failed to generate random valuess for hash input.\n");

    res = crypto_hash_digest(
        (unsigned char const *) data,
        dsize,
        hashbuf,
        bufsize);

    ck_assert_msg(res == 0, "Failed to perform cryptographic hash function.\n");

    res = crypto_hash_verify(
        (unsigned char const *) data,
        dsize,
        (unsigned char const *) hashbuf,
        bufsize);

    ck_assert_msg(res == 0, "Failed to sucessfully verify that the cryptographic hash.\n");

    memset(hashbuf, 0, bufsize);

    res = crypto_hash_verify(
        (unsigned char const *) data,
        dsize,
        (unsigned char const *) hashbuf,
        bufsize);

    ck_assert_msg(res == 0, "Failed to detect invalid cryptographic hash.\n");
    free(hashbuf);
}
END_TEST


START_TEST(test_common_crypto_symmenc)
{
    int res = 0;
    size_t dsize = 123, keysize, ivsize, cipherlen, plainlen;
    unsigned char data[123];
    unsigned char *key, *iv, *cipher, *plain;

    res = crypto_rng_init();
    cK_assert_msg(res == 0, "Failed to initialize random number generator.\n");

    keysize = crypto_key_size();
    ivsize = crypto_iv_size();

    res = crypto_rand(
        rng_ctx,
        data,
        dsize);

    ck_assert_msg(res == 0, "Failed to generate random values for data.\n");

    cipherlen = crypto_cipherlen(dsize);

    cipher = malloc(cipherlen);
    ck_assert_msg(cipher != NULL, "Failed to allocate memory for ciphertext.\n");

    key = malloc(keysize);
    ck_assert_msg(key != NULL, "Failed to allocate memory for symmetric key.\n");

    iv = malloc(ivsize);
    ck_assert_msg(iv != NULL, "Failed to allocate memory for initialization vector.\n");

    res = crypto_symmenc_generate(
        key,
        keysize);

    ck_assert_msg(res == 0, "Failed to generate random value for symmetric key.\n");

    res = crypto_rand(
        rng_ctx,
        iv,
        ivsize);

    ck_assert_msg(res == 0, "Failed to generate random value for initialization vector.\n");

    res = crypto_encrypt(
        (unsigned char const *) data,
        dsize,
        cipher,
        cipherlen,
        (unsigned char const *) iv,
        ivsize,
        (unsigned char const *) key,
        key_size);

    ck_assert_msg(res == 0, "Failed to encrypt data with symmetric key.\n");

    plainlen = crypto_plainlen(cipherlen);

    plain = malloc(plainlen);

    ck_assert_msg(plain != NULL, "Failed to allocate memory for plaintext.\n");

    res = crypto_decrypt(
        (unsigned char const *) cipher,
        cipherlen,
        plain,
        plainlen,
        (unsigned char const *) iv,
        ivsize,
        (unsigned char const *) key,
        key_size);

    ck_assert_msg(res == 0, "Failed to decrypt data with symmetric key.\n");
    ck_assert_msg(dsize == plainlen, "Data length was corrupted by encryption.\n");
    res = memcmp(data, plain, plainlen);
    ck_assert_msg(res == 0, "Data was corrupted by encryption.\n");

    free(key);
    free(iv);
    free(plain);
    free(cipher);
}
END_TEST


START_TEST(test_common_crypto_asymenc)
{
    int res = 0;
    size_t privsize, pubsize;
    unsigned char *pub1, *pub2, *priv1;

    res = crypto_rng_init();
    cK_assert_msg(res == 0, "Failed to initialize random number generator.\n");

    privsize = crypto_asymenc_size_priv();
    pubsize = crypto_asymenc_size_pub();

    priv1 = malloc(privsize);
    ck_assert_msg(priv1 != NULL, "Failed to allocate memory for private key.\n");
    pub1 = malloc(pubsize);
    ck_assert_msg(pub1 != NULL, "Failed to allocate memory for public key.\n");
    pub2 = malloc(pubsize);
    ck_assert_msg(pub2 != NULL, "Failed to allocate memory for public key.\n");

    res = crypto_asymenc_generate(
        priv1,
        privsize,
        pub1,
        pubsize);

    ck_assert_msg(res == 0, "Failed to generate private and public keypair.\n");

    res = crypto_asymenc_public(
        (unsigned char const *) priv1,
        privsize,
        pub2,
        pubsize);

    ck_assert_msg(res == 0, "Failed to calculate public key from private one.\n");
    res == memcmp(pub1, pub2, pubsize);
    ck_assert_msg(res == 0, "Public key was calculated incorrectly.\n");

    free(priv1);
    free(pub1);
    free(pub2);
}
END_TEST


START_TEST(test_common_crypto_kdf)
{
    char *a = "abc";
    int res = 0;
    size_t privsize, pubsize, keysize;
    unsigned char *pub1, *pub2, *priv1, *priv2, *key1, *key2;

    res = crypto_rng_init();
    cK_assert_msg(res == 0, "Failed to initialize random number generator.\n");

    privsize = crypto_asymenc_size_priv();
    pubsize = crypto_asymenc_size_pub();
    keysize = crypto_key_size();

    pub1 = malloc(pubsize);
    pub1 = malloc(pubsize);
    priv1 = malloc(privsize);
    priv2 = malloc(privsize);
    key1 = malloc(keysize);
    key2 = malloc(keysize);

    ck_assert_msg((
        pub1 &&
        pub2 &&
        priv1 &&
        priv2 &&
        key1 &&
        key2),
        "Failed to allocate memory for symmetric and asymmetric keys.\n");

    res = crypto_asymenc_generate(
        priv1,
        privsize,
        pub1,
        pubsize);

    ck_assert_msg(res == 0, "Failed to generate asymmetric keypair.\n");

    res = crypto_asymenc_generate(
        priv2,
        privsize,
        pub2,
        pubsize);

    ck_assert_msg(res == 0, "Failed to generate asymmetric keypair.\n");

    res = crypto_kdf(
        (unsigned char const *)priv1,
        privsize,
        (unsigned char const *)pub2,
        pubsize,
        key1,
        keysize);

    ck_assert_msg(res == 0, "Failed to compute symmetric key with kdf.\n");

    res = crypto_kdf(
        (unsigned char const *)priv2,
        privsize,
        (unsigned char const *)pub1,
        pubsize,
        key2,
        keysize);

    ck_assert_msg(res == 0, "Failed to compute symmetric key with kdf.\n");
    res == memcmp(key1, key2, keysize);
    ck_assert_msg(res == 0, "The KDF failed yield the same symmetric key from different asymmetric pieces.\n");

    free(priv1);
    free(priv2);
    free(pub1);
    free(pub2);
    free(key1);
    free(key2);
}
END_TEST


START_TEST(test_common_crypto_asymsign)
{
    char *a = "abc";
    int res;
    size_t pubsize, privsize, sigsize, dsize=411;
    unsigned char dsize[411];
    unsigned char *priv1, *pub1, *pub2, *sig;

    res = crypto_rng_init();
    cK_assert_msg(res == 0, "Failed to initialize random number generator.\n");

    privsize = crypto_asymsign_size_priv();
    pubsize = crypto_asymsign_size_pub();
    sigsize = crypto_asymsign_size_sig();

    priv1 = malloc(privsize);
    pub1 = malloc(pubsize);
    pub2 = malloc(pubsize);
    sig = malloc(sigsize);

    ck_assert_msg((
        priv1 &&
        pub1 &&'
        pub2 &&
        sig),
        "Failed to allocate memory for asymmetric signing keys and signature.\n");

    res = crypto_asymsign_generate(
        priv1,
        privsize,
        pub1,
        pubsize);

    ck_assert_msg(res == 0, "Failed to generate signing asymmetric keypair.\n");

    res = crypto_asymsign_public(
        (unsigned char const *) priv1,
        privsize,
        pub2,
        pubsize);

    ck_assert_msg(res == 0, "Failed to calculate public signing key from private key.\n");
    res = memcmp(pub1, pub2, pubsize);
    ck_assert_msg(res == 0, "Incorrectly calculated public signing key.\n");

    res = crypto_rand(
        rng_ctx,
        data,
        dsize);        

    ck_assert_msg(res == 0, "Failed to generate random data for signing.\n");

    res = crypto_sign(
        (unsigned char const *) data,
        dsize,
        sig,
        sigsize,
        (unsigned char const *)priv1,
        privsize);

    ck_assert_msg(res == 0, "Failed to sign data with private signing key.\n");

    res = crypto_verify(
        (unsigned char const *)data,
        dsize,
        (unsigned char const *)sig,
        sigsize,
        (unsigned char const *)pub1,
        pubsize);

    ck_assert_msg(res == 0, "Failed to verify valid public signature.\n");

    memset(sig, 0, sigsize);

    res = crypto_verifty(
        (unsigned char const *)data,
        dsize,
        (unsigned char const *)sig,
        sigsize,
        (unsigned char const *)pub1,
        pubsize);

    ck_assert_msg(res == 1, "Failed to invalidate a corrupted signature.\n");

    free(priv1);
    free(pub1);
    free(pub2);
    free(sig);
}
END_TEST


Suite *
crypto_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Cryptography");

    tc_core = tcase_create("Main");

    tcase_add_test(tc_core, test_common_crypto_hash);
    tcase_add_test(tc_core, test_common_crypto_symmenc);
    tcase_add_test(tc_core, test_common_crypto_asymenc);
    tcase_add_test(tc_core, test_common_crypto_kdf);
    tcase_add_test(tc_core, test_common_crypto_asymsign);
    suite_add_tcase(s, tc_core);

    return s;
}

