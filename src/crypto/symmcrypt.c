#include "aid/crypto/symmcrypt.h"

#include "tweetnacl.h"

#include "aid/core/error.h"
#include "aid/core/log.h"
#include "aid/crypto/symmkeys.h"


static int
symmcrypt_encrypt_xsalsa20(
    unsigned char const *data,
    size_t dsize,
    unsigned char *cipherbuf,
    unsigned char const *iv,
    unsigned char const *key)
{
    int state = 0;

    if (crypto_stream_xor(
        cipherbuf,
        data,
        dsize,
        iv,
        key) != 0)
    {
        AID_LOG_ERROR(state = AID_ERR_CRYPTO, NULL);
    }

    return state;
}


static int
symmcrypt_decrypt_xsalsa20(
    unsigned char const *data,
    size_t dsize,
    unsigned char *plainbuf,
    unsigned char const *iv,
    unsigned char const *key)
{
    int state = 0;

    if (crypto_stream_xor(
        plainbuf,
        data,
        dsize,
        iv,
        key) != 0)
    {
        AID_LOG_ERROR(state = AID_ERR_CRYPTO, NULL);
    }

    return state;
}


static size_t
symmcrypt_cipherlen_xsalsa20(
    size_t plainsize)
{
    return plainsize;
}


static size_t
symmcrypt_plainlen_xsalsa20(
    size_t ciphersize)
{
    return ciphersize;
}


int
aid_symmcrypt_encrypt(
    aid_symmcrypt_t type,
    unsigned char const *data,
    size_t dsize,
    unsigned char *cipherbuf,
    size_t bufsize,
    unsigned char const *iv,
    size_t ivsize,
    aid_symmkeys_key_t const *key)
{
    aid_symmcrypt_index_t const *index;
    int state = 0;

    if (!data || !cipherbuf || !iv || !key) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(index = aid_symmcrypt_index(type))) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "Invalid symmetric encryption algorithm was specified");
        goto out;
    }

    if (index->key_type != key->type) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "The type of the provided key is not correct for the specified encryption algorithm");
        goto out;
    }

    if (index->iv_size != ivsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "The size of provided initialization vector is not valid for the specified algorithm");
    }

    if (index->cipherlen(dsize) != bufsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "Provided buffer for ciphertext is not of correct size");
        goto out;
    }

    if (!key->key) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "A NULL key was provided");
        goto out;
    }

    if ((state = index->encrypt(
        data,
        dsize,
        cipherbuf,
        iv,
        key->key)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, NULL);
        goto out;
    }

out:
    return state;
}


int
aid_symmcrypt_decrypt(
    aid_symmcrypt_t type,
    unsigned char const *data,
    size_t dsize,
    unsigned char *plainbuf,
    size_t bufsize,
    unsigned char const *iv,
    size_t ivsize,
    aid_symmkeys_key_t const *key)
{
    aid_symmcrypt_index_t const *index;
    int state = 0;

    if (!data || !plainbuf || !iv || !key) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(index = aid_symmcrypt_index(type))) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "Invalid symmetric decryption algorithm was specified");
        goto out;
    }

    if (index->key_type != key->type) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "The type of the provided key is not correct for the specified decryption algorithm");
        goto out;
    }

    if (index->iv_size != ivsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "The size of provided initialization vector is not valid for the specified algorithm");
    }

    if (index->plainlen(dsize) != bufsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "Provided buffer for plaintext is not of correct size");
        goto out;
    }

    if (!key->key) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "A NULL key was provided");
        goto out;
    }

    if ((state = index->decrypt(
        data,
        dsize,
        plainbuf,
        iv,
        key->key)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, NULL);
        goto out;
    }

out:
    return state;
}


static aid_symmcrypt_index_t const symmcrypt_index[AID_SYMMCRYPT_NUM] =
{
    {
        AID_SYMMKEYS_XSALSA20,
        24,
        "XSALSA20",
        &symmcrypt_encrypt_xsalsa20,
        &symmcrypt_decrypt_xsalsa20,
        &symmcrypt_cipherlen_xsalsa20,
        &symmcrypt_plainlen_xsalsa20
     }
};


aid_symmcrypt_index_t const *
aid_symmcrypt_index(
    aid_symmcrypt_t type)
{

    if (!type || type > AID_SYMMCRYPT_NUM) {
        AID_LOG_ERROR(AID_ERR_BAD_PARAM, "Invalid symmetric cipher algorithm specified");
        return NULL;
    }
    else {
        return &(symmcrypt_index[type - 1]);
    }

}
