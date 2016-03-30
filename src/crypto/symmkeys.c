#include "aid/crypto/symmkeys.h"

#include <string.h>
#include <stdlib.h>

#include "aid/crypto/general.h"
#include "aid/core/error.h"
#include "aid/core/log.h"
#include "aid/core/utils.h"


int
aid_symmkeys_generate(
    aid_symmkeys_t type,
    rng_function_t f_rng,
    void *p_rng,
    aid_symmkeys_key_t *key)
{
    aid_symmkeys_index_t const *index;
    int state = 0;

    if (!f_rng || !p_rng || !key) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!(index = aid_symmkeys_index(type))) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    key->type = type;

    if (!(key->key = malloc(index->key_size))) {
        AID_LOG_ERROR(state = AID_ERR_NO_MEM, NULL);
        goto out;
    }

    memset(key->key, 0, index->key_size);

    if(f_rng(
        p_rng,
        key->key,
        index->key_size) != 0)
    {
        AID_LOG_ERROR(state = AID_ERR_RNG, "Failed to generate random bytes for symmetric key");
        goto cleanup_key;
    }

    key->type = type;

    return state;

cleanup_key:
    aid_symmkeys_cleanup(key);
out:
    return state;
}


int
aid_symmkeys_to_binary(
    aid_symmkeys_key_t const *key,
    unsigned char *binbuf,
    size_t bufsize)
{
    int state = 0;
    size_t keysize;

    if (!key || !binbuf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if ((bufsize - 1) != (keysize = aid_symmkeys_index(key->type)->key_size)) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARM, NULL);
        goto out;
    }

    binbuf[0] = (unsigned char) key->type;
    memcpy(binbuf + 1, key->key, keysize);

out:
    return state;
}


int
aid_symmkeys_from_binary(
    unsigned char const *binbuf,
    size_t bufsize,
    aid_symmkeys_key_t *key)
{
    int state = 0;
    size_t keysize;

    if (!key || !binbuf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if ((bufsize - 1) != (keysize = aid_symmkeys_index(key->type)->key_size)) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(key->key = malloc(keysize))) {
        AID_LOG_ERROR(state = AID_ERR_NO_MEM, NULL);
        goto out;
    }

    key->type = binbuf[0];
    memcpy(key->key, binbuf + 1, keysize);

out:
    return state;
}


void
aid_symmkeys_cleanup(
    aid_symmkeys_key_t *key)
{
    aid_symmkeys_index_t const *index;

    if (key) {

        if (key->key && (index = aid_symmkeys_index(key->type))) {
            aid_utils_wipe(key->key, index->key_size);
            free(key->key);
            key->key= NULL;
        }

        key->type = 0;
    }
}


static aid_symmkeys_index_t const symmkeys_index[AID_SYMMKEYS_NUM] =
{
    {
        32,
        "AES256 CBC"
    },
    {
        32,
        "XSALSA20"
    }
};


aid_symmkeys_index_t const *
aid_symmkeys_index(
    aid_symmkeys_t type)
{
    
    if (!type || type > AID_SYMMKEYS_NUM) {
        AID_LOG_ERROR(AID_ERR_BAD_PARAM, "Invalid symmetric key type specified");
        return NULL;
    }
    else {
        return &(symmkeys_index[type - 1]);
    }

}


