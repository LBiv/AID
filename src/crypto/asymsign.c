#include "aid/crypto/asymsign.h"

#include "tweetnacl.h"

#include "aid/core/error.h"
#include "aid/core/log.h"
#include "aid/core/util.h"
#include "aid/crypto/asymkeys.h"


typedef int (*asymsign_sign_t)(
    unsigned char const *,
    size_t,
    unsigned char *,
    unsigned char const *);

typedef int (*asymsign_verify_t)(
    unsigned char const *,
    size_t,
    unsigned char const *,
    unsigned char const *);

typedef struct { 
    aid_asymkeys_t key_type; 
    size_t sig_size; 
    char const *name; 
    asymsign_sign_t sign;
    asymsign_verify_t verify;
} aid_asymsign_index_t;


static int
asymsign_sign_eddsa(
    unsigned char const *data,
    size_t dsize,
    unsigned char *sigbuf,
    unsigned char const *key)
{
    int state = 0;
    unsigned char *tmp;
    u64 smlen;

    if (!(tmp = malloc(64 + dsize))) {
        state = AID_LOG_ERROR(AID_ERR_NO_MEM, NULL);
        goto out;
    }

    if (crypto_sign(
        tmp,
        &smlen,
        data,
        dsize,
        key) != 0)
    {
        state = AID_LOG_ERROR(AID_ERR_CRYPTO, "Failed to sign data with EDDSA");
        goto cleanup_tmp;
    }

    memcpy(sigbuf, tmp, 64);

cleanup_tmp:
    free(tmp);
out:
    return state;
}


static int
asymsign_verify_eddsa(
    unsigned char const *data,
    size_t dsize,
    unsigned char const *sigbuf,
    unsigned char const *key)
{
    int state = 0, res;
    unsigned char *tmp_m, *tmp_sm;
    u64 mlen;

    if (!(tmp_m = malloc(64 + dsize))) {
        state = AID_LOG_ERROR(AID_ERR_NO_MEM, NULL);
        goto out;
    }

    if(!(tmp_sm = malloc(64 + dsize))) {
        free(tmp_m);
        state = AID_LOG_ERROR(AID_ERR_NO_MEM, NULL);
        goto out;
    }

    memcpy(tmp_m, sigbuf, 64);
    memcpy(tmp_m, data, dsize);
    memcpy(tmp_sm, tmp_m, dsize + 64);

    res = crypto_sign_open(
        tmp_m,
        &mlen,
        (const u8)tmp_sm,
        dsize+64,
        key);

    free(tmp_m);
    free(tmp_sm);

    if (res == 0) {
        goto out;
    }
    else if (res == -1) {
        state = 1;
        goto out;
    }
    else {
        state = AID_LOG_ERROR(AID_ERR_CRYPTO, "An error occurred while verifying EDDSA signature");
        goto out;
    }

out:
    return state;
}


aid_asymsign_index_t const *
aid_asymsign_index(
    aid_asymsign_t type)
{
    switch (type) {

    case AID_ASYMSIGN_EDDSA:
        return (aid_asymkeys_index_t const *) &{
            AID_ASYMKEYS_ED25519,
            64,
            "EdDSA Curve25519",
            &asymsign_sign_eddsa,
            &asymsign_verify_eddsa
        };
    default:
        AID_LOG_ERROR(AID_ERR_BAD_PARAM, "Invalid asymmetric signing algorithm specified");
        return NULL;

    }

}


int
aid_asymsign_sign(
    aid_asymsign_t type,
    unsigned char const *data,
    size_t dsize,
    aid_asymkeys_private_t const *key,
    unsigned char *sigbuf,
    size_t bufsize)
{

    aid_asymkeys_index_t const *index;
    int state = 0;

    if (!data || !key || !sigbuf) {
        state = AID_LOG_ERROR(AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(index = aid_asymkeys_index(type))) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, "Invalid signing algorithm was specified");
        goto out;
    }

    if (index->key_type != key->type) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, "The type of the provided key is not correct for the specified signing algorithm");
        goto out;
    }

    if (index->sig_size != bufsize) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, "The provided buffer for signature is not of correct size");
        goto out;
    }

    if (!key->key) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, "A NULL key was provided");
        goto out;
    }

    if ((state = index->sign(
        data,
        dsize,
        sigbuf,
        (unsigned char const *)key->key)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, NULL);
        goto out;
    }

out:
    return state;
}


int
aid_asymsign_verify(
    aid_asymsign_t type,
    unsigned char const *data,
    size_t dsize,
    unsigned char const *sigbuf,
    size_t bufsize,
    aid_asymkeys_public_t const *key)
{

    aid_asymkeys_index_t const *index;
    int state = 0;

    if (!data || !key || !sigbuf) {
        state = AID_LOG_ERROR(AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(index = aid_asymkeys_index(type))) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (index->key_type != key->type) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, "The type of the provided key is not correct for the specified signing algorithm");
        goto out;
    }

    if (index->sig_size != bufsize) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, "The provided signature buffer is not of correct size");
        goto out;
    }

    if (!key->key) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, "A NULL key was provided");
        goto out;
    }

    if ((state = index->verify(
        data,
        dsize,
        sigbuf,
        (unsigned char const *)key->key)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, NULL);
        goto out;
    }

out:
    return state;
}
