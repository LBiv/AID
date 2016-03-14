#include "aid/crypto/symmkeys.h"

#include "aid/crypto/general.h"
#include "aid/core/error.h"
#include "aid/core/log.h"
#include "aid/core/util.h"

typedef struct {
    size_t key_size;
    char const *name;
} aid_symmkeys_index_t;


aid_symmkeys_index_t const *
aid_symmkeys_index(
    aid_symmkeys_t type)
{
    switch (type) {

    case AID_SYMMKEYS_AES256:
        return (aid_symmkeys_index_t const *) &{
            32,
            "AES256 CBC"
        };
    case AID_SYMMKEYS_XSALSA20:
        return (aid_symmkeys_index_t const *) &{
            32,
            "XSALSA20"
        };
    default:
       AID_LOG_ERROR(AID_ERR_BAD_PARAM, "Invalid symmetric key type specified");
       return NULL;

    }
    
}


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
        state = AID_LOG_ERROR(AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!(index = aid_symmkeys_index(type))) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    key->type = type;

    if (!(key->key = malloc(index->key_size))) {
        state = AID_LOG_ERROR(AID_ERR_NO_MEM, NULL);
        goto out;
    }

    memset(key->key, 0, index->key_size);

    if(f_rng(
        p_rng,
        key->key,
        index->key_size) != 0)
    {
        state = AID_LOG_ERROR(AID_ERR_RNG, "Failed to generate random bytes for symmetric key");
        goto cleanup_key;
    }

    return state;

cleanup_key:
    free(key->key);
out:
    return state;
}


void
aid_symmkeys_cleanup(
    aid_symmkeys_key_t *key)
{
    adi_symmkeys_index_t const *index;

    if (key) {

        if (key->key && (index = aid_symmkeys_index(key->type))) {
            aid_utils_wipe(key->key, index->key_size);
            free(key->key);
            key->key= NULL;
        }

        key->type = 0;
    }
}
