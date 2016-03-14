#include "aid/crypto/hash.h"

#include "tweetnacl.h"

#include "aid/core/error.h"
#include "aid/core/log.h"

typedef int (*hash_digest_t) (
    unsigned char const *,
    size_t,
    unsigned char *);

typedef int (*hash_verify_t) (
    unsigned char const *,
    size_t,
    unsigned char const *);

typedef struct {
    size_t hash_size;
    char const *name;
    hash_digest_t digest;
    hash_verify_t verify;
} aid_hash_index_t;


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
        state = AID_LOG_ERROR(AID_ERR_CRYPTO, "Failed to computer SHA-512 hash");
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
        state = AID_LOG_ERROR(AID_ERR_CRYPTO, "Failed to computer SHA-512 hash");
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



aid_hash_index_t const *
aid_hash_index(
    aid_hash_t type)
{
    switch (type) {

    case AID_HASH_SHA512:
        return (aid_hash_index_t const *) &{
            64,
            "SHA-512",
            &hash_digest_sha512,
            &hash_verify_sha512
        };
    default:
        AID_LOG_ERROR(AID_ERR_BAD_PARAM, "Invalid hash algorithm specified");
        return NULL;
    }

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
        state = AID_LOG_ERROR(AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(index = aid_hash_index(type))) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (index->hash_size != bufsize) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, "The provided buffer size does not match the size required by algorithm");
        goto out;
    }

    if ((state = index->digest(
        data,
        dsize,
        hashbuf,
        bufsize) < 0))
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
    unsigned char *hashbuf,
    size_t bufsize)
{
    aid_hash_index_t const *index;
    int state = 0;

    if (!data || !hashbuf) {
        state = AID_LOG_ERROR(AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(index = aid_hash_index(type))) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (index->hash_size != bufsize) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, "The provided buffer size does not match the size required by algorithm");
        goto out;
    }

    if ((state = index->verify(
        data,
        dsize,
        hashbuf,
        bufsize) < 0))
    {
        AID_LOG_ERROR(AID_ERR_RETURN, NULL);
        goto out;
    }

out:
    return state;
}

