#include "aid/crypto/asymkeys.h"

#include <string.h>
#include <stdlib.h>

#include "tweetnacl.h"
#include "aid/core/error.h"
#include "aid/core/log.h"
#include "aid/core/utils.h"


static int
asymkeys_generate_ed25519(
    rng_function_t f_rng,
    void *p_rng,
    unsigned char *priv,
    unsigned char *pub)
{
    int state = 0;

    if (f_rng(
        p_rng,
        priv,
        32) != 0)
    {
        AID_LOG_ERROR(state = AID_ERR_RNG, "Failed to generate random bytes for private ed25519 key");
        goto out;
    }

    if (crypto_sign_pub(
        priv,
        pub) != 0)
    {
        AID_LOG_ERROR(state = AID_ERR_CRYPTO, "Failed to calculate ed25519 public signing key");
    }

out:
  return state;
}


static int
asymkeys_generate_x25519(
    rng_function_t f_rng,
    void *p_rng,
    unsigned char *priv,
    unsigned char *pub)
{
    int state = 0;

    if (f_rng(
        p_rng,
        priv,
        32) != 0)
    {
        AID_LOG_ERROR(state = AID_ERR_RNG, "Failed to generate random bytes for private x25519 key");
        goto out;
    }

    if (crypto_scalarmult_base(
        pub,
        (unsigned char const *)priv) != 0)
    {
        AID_LOG_ERROR(state = AID_ERR_CRYPTO, "Failed to calculate public x25519 key");
        goto out;
    }

out:
    return state;
}


static int
asymkeys_public_ed25519(
    unsigned char const *priv,
    unsigned char *pub)
{
    memcpy(pub, priv + 32, 32);

    return 0;
}


static int
asymkeys_public_x25519(
    unsigned char const *priv,
    unsigned char *pub)
{
    int state = 0;

    if (crypto_scalarmult_base(
        pub,
        (unsigned char const *)priv) != 0)
    {
        AID_LOG_ERROR(state = AID_ERR_CRYPTO, "Failed to calculate public x25519 key");
        goto out;
    }

out:
    return state;
}


int
aid_asymkeys_generate(
    aid_asymkeys_t type,
    rng_function_t f_rng,
    void *p_rng,
    aid_asymkeys_private_t *priv,
    aid_asymkeys_public_t *pub)
{
    aid_asymkeys_index_t const *index;
    int state = 0;

    if (!f_rng || !p_rng || !priv || !pub) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!(index = aid_asymkeys_index(type))) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(priv->key = malloc(index->priv_size))) {
        AID_LOG_ERROR(state = AID_ERR_NO_MEM, NULL);
        goto out;
    }

    memset(priv->key, 0, index->priv_size);

    if (!(pub->key = malloc(index->pub_size))) {
        AID_LOG_ERROR(state = AID_ERR_NO_MEM, NULL);
        goto cleanup_priv;
    }

    memset(pub->key, 0, index->pub_size);

    if ((state = index->generate(
        f_rng,
        p_rng,
        priv->key,
        pub->key)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, NULL);
        goto cleanup_pub;
    }

    priv->type = type;
    pub->type = type;

    return state;

cleanup_pub:
    aid_asymkeys_cleanup_pub(pub);
cleanup_priv:
    aid_asymkeys_cleanup_priv(priv);
out:
    return state;
}


int
aid_asymkeys_public(
    aid_asymkeys_private_t const *priv,
    aid_asymkeys_public_t *pub)
{
    aid_asymkeys_index_t const *index;
    int state = 0;

    if (!priv || !pub || !priv->key) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!(index = aid_asymkeys_index(priv->type))) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(pub->key = malloc(index->pub_size))) {
        AID_LOG_ERROR(state = AID_ERR_NO_MEM, NULL);
        goto out;
    }

    memset(pub->key, 0, index->pub_size);

    if ((state = index->pub(
        priv->key,
        pub->key)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, NULL);
        goto cleanup_pub;
    }

    pub->type = priv->type;

    return state;

cleanup_pub:
    aid_asymkeys_cleanup_pub(pub);
out:
    return state;
}


int
aid_asymkeys_to_binary_priv(
    aid_asymkeys_private_t const *priv,
    unsigned char *binbuf,
    size_t bufsize)
{
    int state = 0;
    size_t privsize;

    if (!priv || !binbuf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (bufsize != ((privsize = aid_asymkeys_index(priv->type)->priv_size) + 1)) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    binbuf[0] = (unsigned char) priv->type;
    memcpy(binbuf + 1, priv->key, privsize);

out:
    return state;
}


int
aid_asymkeys_to_binary_pub(
    aid_asymkeys_public_t const *pub,
    unsigned char *binbuf,
    size_t bufsize)
{
    int state = 0;
    size_t pubsize;

    if (!pub || !binbuf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (bufsize != ((pubsize = aid_asymkeys_index(pub->type)->pub_size) + 1)) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    binbuf[0] = (unsigned char) pub->type;
    memcpy(binbuf + 1, pub->key, pubsize);

out:
    return state;
}


int
aid_asymkeys_from_binary_priv(
    unsigned char const *binbuf,
    size_t bufsize,
    aid_asymkeys_private_t *priv)
{
    int state = 0;
    size_t privsize;

    if (!priv || !binbuf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if ((bufsize - 1) != (privsize = aid_asymkeys_index(priv->type)->priv_size)) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(priv->key = malloc(privsize))) {
        AID_LOG_ERROR(state = AID_ERR_NO_MEM, NULL);
        goto out;
    }

    priv->type = binbuf[0];
    memcpy(priv->key, binbuf + 1, privsize);

out:
    return state;
}


int
aid_asymkeys_from_binary_pub(
    unsigned char const *binbuf,
    size_t bufsize,
    aid_asymkeys_public_t *pub)
{
    int state = 0;
    size_t pubsize;

    if (!pub || !binbuf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if ((bufsize - 1) != (pubsize = aid_asymkeys_index(pub->type)->pub_size)) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(pub->key = malloc(pubsize))) {
        AID_LOG_ERROR(state = AID_ERR_NO_MEM, NULL);
        goto out;
    }

    pub->type = binbuf[0];
    memcpy(pub->key, binbuf + 1, pubsize);

out:
    return state;
}
    

void
aid_asymkeys_cleanup_priv(
    aid_asymkeys_private_t *priv)
{
    aid_asymkeys_index_t const *index;

    if (priv) {

        if (priv->key && (index = aid_asymkeys_index(priv->type))) {
            aid_utils_wipe(priv->key, index->priv_size);
            free(priv->key);
            priv->key = NULL;
        }

        priv->type = 0;
    }
}


void
aid_asymkeys_cleanup_pub(
    aid_asymkeys_public_t *pub)
{
    if (pub) {

        if (pub->key) {
            free(pub->key);
            pub->key = NULL;
        }

        pub->type = 0;
    }
}


static aid_asymkeys_index_t const asymkeys_index[AID_ASYMKEYS_NUM] =
{
    {
        64,
        32,
        "Signing Curve25519",
        &asymkeys_generate_ed25519,
        &asymkeys_public_ed25519
     },
     {
        32,
        32,
        "Encryption Curve25519",
        &asymkeys_generate_x25519,
        &asymkeys_public_x25519
    }
};


aid_asymkeys_index_t const *
aid_asymkeys_index(
    aid_asymkeys_t type)
{

    if (!type || type > AID_ASYMKEYS_NUM) {
        AID_LOG_ERROR(AID_ERR_BAD_PARAM, "Invalid asymmetric key type specified");
        return NULL;
    }
    else {
        return &(asymkeys_index[type - 1]);
    }

}
