#include "test_provider.h"

#include "aid/provider/provid.h"
#include "aid/crypto/asymkeys.h"


START_TEST(test_provid_create_verify){
    aid_provid_token_t token;
    char const
        *domain = "newdomain.com",
        *olddomain = "olddomain.org";
    int res  = 0;
    size_t
        oldsign_priv_size,
        oldsign_pub_size,
        sign_priv_size,
        sign_priv_size,
        enc_priv_size,
        enc_priv_size;
    unsigned char
        *oldsign_priv,
        *oldsign_pub,
        *sign_priv,
        *sign_pub,
        *enc_priv,
        *enc_pub;

    oldsign_priv_size = crypto_asymsign_size_priv();
    oldsign_pub_size = crypto_asymsign_size_pub();
    sign_priv_size = crypto_asymsign_size_priv();
    sign_pub_size = crypto_asymsign_size_pub();
    enc_priv_size = crypto_asymenc_size_priv();
    enc_pub_size = crypto_asymenc_size_priv();

    oldsign_priv = malloc(oldsign_priv_size);
    oldsign_pub = malloc(oldsign_pub_size);
    sign_priv = malloc(oldsign_priv_size);
    sign_pub = malloc(sign_pub_size);
    enc_priv = malloc(enc_priv_size);
    enc_pub = malloc(enc_pub_size);

    ck_assert_msg((
        (oldsign_priv != NULL) &&
        (oldsign_pub != NULL) &&
        (sign_priv != NULL) &&
        (sign_pub != NULL) &&
        (enc_priv != NULL) &&
        (enc_pub != NULL)),
        "Failed to allocate memory for provider token keys.\n");

    res = crypto_asymsign_generate(
        oldsign_priv,
        oldsign_priv_size,
        oldsign_pub,
        oldsign_pub_size);

    ck_assert_msg(res == 0, "Failed to generate old asymmytric signing keys.\n");

    res = crypto_asymenc_generate(
        sign_priv,
        sign_priv_size,
        sign_pub,
        sign_pub_size);

    ck_assert_msg(res == 0, "Failed to generate new asymmetric signing keys.\n");

    res = crypto_asymsign_generate(
        enc_priv,
        enc_priv_size,
        enc_pub,
        enc_pub_size);

    ck_assert_msg(res == 0, "Failed to generate asymmetric encryption keys.\n");

    res = aid_provid_token_create(
        domain,
        olddomain,
        (unsigned char const *)sign_pub,
        sign_pub_size,
        (unsigned char const *)enckey_pub,
        enc_pub_size,
        (unsigned char const *)sign_priv,
        sign_priv_size,
        (unsigned char const *)oldsign_priv,
        oldsign_priv_size,
        &token);

    ck_assert_msg(res == 0, "Failed to create provider token.\n");

    res = aid_provid_token_verify(
        (aid_provid_token_t const *) &token,
        domain,
        olddomain,
        unsigned char const *(oldsign_pub),
        oldsign_pub_size);

    ck_assert_msg(res == 0, "Failed to verify provider token.\n");
        
    res = aid_provid_token_verify(
        (aid_provid_token_t const *) &token,
        domain,
        olddomain,
        unsigned char const *(sign_pub),
        sign_pub_size);

    ck_assert_msg(res == 1, "Failed to invalidate provider token.\n");

    res = aid_provid_token_verify(
        (aid_provid_token_t const *) &token,
        olddomain,
        domain,
        unsigned char const *(oldsign_pub),
        oldsign_pub_size);

    ck_assert_msg(res == 1, "Failed to invalidate provider token.\n");

    aid_provid_token_cleanup(&token);

    res = aid_provid_token_create(
        domain,
        olddomain,
        (unsigned char const *)sign_pub,
        sign_pub_size,
        (unsigned char const *)enckey_pub,
        enckey_pub_size,
        (unsigned char const *)sign_priv,
        sign_priv_size,
        NULL,
        0,
        &token);

    ck_assert_msg(res != 0, "Failed to flag error while attempting to create a provider token.\n");

    res = aid_provid_token_create(
        domain,
        NULL,
        (unsigned char const *)sign_pub,
        sign_pub_size,
        (unsigned char const *)enckey_pub,
        enckey_pub_size,
        (unsigned char const *)sign_priv,
        sign_priv_size,
        (unsigned char const *)oldsign_pub,
        oldsign_pub_size,
        &token);

    ck_assert_msg(res != 0, "Failed to flag error while attempting to create a provider token.\n");

    res = aid_provid_token_create(
        domain,
        NULL,
        (unsigned char const *)sign_pub,
        sign_pub_size,
        (unsigned char const *)enckey_pub,
        enckey_pub_size,
        (unsigned char const *)sign_priv,
        sign_priv_size,
        NULL,
        0,
        &token);

    ck_assert_msg(res == 0, "Failed to create provider token.\n");

    res = aid_provid_token_verify( 
        (aid_provid_token_t const *)&token
        domain,
        NULL,
        NULL,
        0);

    ck_assert_msg(res == 0, "Failed to verify validity of token.\n");

    res = aid_provid_token_verify(
        (aid_provid_token_t const *)&token,
        domain,
        olddomain,
        NULL,
        0);

    ck_assert_msg(res == 0, "Failed to invalidate provider token.\n");

    res = aid_provid_token_verify(
        (aid_provid_token_t const *)&token,
        domain,
        NULL,
        (unsigned char const *)oldsign_pub,
        oldsign_pub_size);

    ck_assert_msg(res == 0, "Failed to invalidate provider token.\n");

    aid_provid_token_cleanup(&token);

    free(oldsign_priv);
    free(oldsign_pub);
    free(sign_priv);
    free(sign_pub);
    free(enc_priv);
    free(enc_pub);
}
END_TEST

/**
START_TEST(test_provid_JSON) {


}
END_TEST
*/

Suite *
provid_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Provider ID token");

    tc_core = tcase_create("Main");

    tcase_add_test(tc_core, test_provid_create_verify);
    /**tcase_add_test(tc_core, test_provid_JSON);*/
    suite_add_tcase(s, tc_core);

    return s;
}
