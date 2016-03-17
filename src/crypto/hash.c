#include "aid/crypto/hash.h"


#include <string.h>

#include "tweetnacl.h"

#include "aid/core/error.h"
#include "aid/core/log.h"


static int
hash_digest_sha512(
    unsigned char const *data,
    size_t dsize,
    unsigned char *hashbuf)
{
    int state = 0;

    if (crypto_hash(
        hashbuf,
        data,
        dsize) != 0)
    {
        AID_LOG_ERROR(state = AID_ERR_CRYPTO, "Failed to computer SHA-512 hash");
        goto out;
    }

out:
    return state;
}


static int
hash_verify_sha512(
    unsigned char const *data,
    size_t dsize,
    unsigned char const *hashbuf)
{
    int state = 0;
    unsigned char tmp[64];

    if (crypto_hash(
        tmp,
        data,
        dsize) != 0)
    {
        AID_LOG_ERROR(state = AID_ERR_CRYPTO, "Failed to computer SHA-512 hash");
        goto out;
    }

    if (memcmp(
        hashbuf,
        tmp,
        64) == 0)
    {
        state = 0;
    }
    else {
        state = 1;
    }

out:
    return state;
}


int
aid_hash_digest(
    aid_hash_t type,
    unsigned char const *data,
    size_t dsize,
    unsigned char *hashbuf,
    size_t bufsize)
{
    aid_hash_index_t const *index;
    int state = 0;

    if (!data || !hashbuf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(index = aid_hash_index(type))) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (index->hash_size != bufsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "The provided buffer size does not match the size required by algorithm");
        goto out;
    }

    if ((state = index->digest(
        data,
        dsize,
        hashbuf)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, NULL);
        goto out;
    }

out:
    return state;
}


int
aid_hash_verify(
    aid_hash_t type,
    unsigned char const *data,
    size_t dsize,
    unsigned char const *hashbuf,
    size_t bufsize)
{
    aid_hash_index_t const *index;
    int state = 0;

    if (!data || !hashbuf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(index = aid_hash_index(type))) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (index->hash_size != bufsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "The provided buffer size does not match the size required by algorithm");
        goto out;
    }

    if ((state = index->verify(
        data,
        dsize,
        hashbuf)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, NULL);
        goto out;
    }

out:
    return state;
}


static aid_hash_index_t const hash_index[AID_HASH_NUM] =
{
     {
        64,
        "SHA-512",
        &hash_digest_sha512,
        &hash_verify_sha512
    }
};


aid_hash_index_t const *
aid_hash_index(
    aid_hash_t type)
{

    if (!type || type > AID_HASH_NUM) {
        AID_LOG_ERROR(AID_ERR_BAD_PARAM, "Invalid hash algorithm specified");
        return NULL;
    }
    else {
        return &(hash_index[type - 1]);
    }

}

