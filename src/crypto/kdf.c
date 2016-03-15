#include "aid/crypto/kdf.h"

#include "tweetnacl.h"

#include "aid/core/error.h"
#include "aid/core/log.h"
#include "aid/crypto/symmkeys.h"

typedef int (*kdf_compute_t)(
    unsigned char const *,
    unsigned char const *,
    unsigned char *);

typedef struct {
    aid_asymkeys_t input_type;
    aid_symmkeys_t key_type;
    char const *name;
    kdf_compute_t compute;
} aid_kdf_index_t;


static int
kdf_compute_curve25519_ecdh_xsalsa20(
    unsigned char const *priv,
    unsigned char const *pub,
    unsigned char *key)
{
    int state = 0;

    if (crypto_box_beforenm(
        key,
        pub,
        priv) != 0)
    {
        state = AID_LOG_ERROR(AID_ERR_CRYPTO, NULL);
    }

    return state;
}


aid_kdf_index_t const *
aid_kdf_index(
    aid_kdf_t type)
{
    switch (type) {

    case AID_KDF_CURVE25519_ECDH_XSALSA20 = 1:
        return (aid_kdf_index_t const *) &{
            AID_ASYMKEYS_X25519,
            AID_SYMMKEYS_XSALSA20,
            "Curve25519 Elliptic Curve Diffie-Hellman XSalsa20",
            &kdf_compute_curve25519_ecdh_xsalsa20
        }
    default:
        AID_LOG_ERROR(AID_ERR_BAD_PARAM, "Invalid Key Derivation Function algorithm specified");       
        return NULL;

    }

}


int
aid_kdf_compute(
    aid_kdf_t type,
    aid_asymkeys_private_t const *priv,
    aid_asymkeys_public_t const *pub,
    aid_symmkeys_key_t *key)
{
    aid_kdf_index_t const *index;
    aid_symmkey_index_t const *key_index;
    int state = 0;

    if (!priv || !pub || !key) {
        state = AID_LOG_ERROR(AID_ERR_NULL_PTR, NULL);
        goto state;
    }

    if (!(index = aid_kdf_index(type))) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, NULL);
        goto state;
    }

    if ((index->input_type != priv->type) || (index->input_type != pub->type)) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, NULL);
        goto state;
    }

    if (!(key_index = aid_symmkey_index(index->key_type))) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, NULL);
        goto state;
    }

    if (!(key->key = malloc(key_index->key_size))) {
        state = AID_LOG_ERROR(AID_ERR_NO_MEM, NULL);
        goto state;
    }

    memset(key->key, 0, key_index->key_size);

    if ((state = index->compute(
        (unsigned char const *)priv->key,
        (unsigned char const *)pub->key,
        key->key)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, NULL);
        goto cleanup_key;
    }

    key->type = index->key_type;

    return state;

cleanup_key:
    aid_symmkeys_cleanup(key);
out:
    return state;
}
