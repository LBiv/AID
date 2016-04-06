#include "aid/common/crypto.h"


#include "aid/core/error.h"
#include "aid/core/log.h"
#include "aid/core/utils.h"
#include "aid/crypto/hash.h"
#include "aid/crypto/kdf.h"
#include "aid/crypto/asymkeys.h"
#include "aid/crypto/asymsign.h"
#include "aid/crypto/symmcrypt.h"
#include "aid/crypto/symmkeys.h"

extern __thread void *rng_ctx;


int
crypto_rng_init(void) {
    return 0;
}


int
crypto_rand(
    void *ctx,
    unsigned char *buf,
    size_t bufsize)
{
    return aid_utils_rand(
        ctx,
        buf,
        bufsize);
}


/** cryptographic hash **/
size_t
crypto_hash_size(void)
{
    return aid_hash_index(CURRENT_HASH)->hash_size + 1;
}

int
crypto_hash_digest(
    unsigned char const *data,
    size_t dsize,
    unsigned char *hashbuf,
    size_t bufsize)
{
    data[0] = (unsigned char)CURRENT_HASH;

    return aid_hash_digest(
        CURRENT_HASH,
        data + 1,
        dsize - 1,
        hashbuf,
        bufsize);
}

// 0 if verified successfully
// 1 if failed to verify
int
crypto_hash_verify(
    unsigned char const *data,
    size_t dsize,
    unsigned char const *hashbuf,
    size_t bufsize)
{
    aid_hash_t type = data[0];

    return aid_hash_verify(
        type,
        data + 1,
        dsize - 1,
        hashbuf,
        bufsize);
}


/** symmetric encryption crypto */
size_t
crypto_key_size(void) {
    return aid_symmkeys_index(CURRENT_SYMM_ENCKEY)->key_size + 1;
}

size_t
crypto_iv_size(void) {
    return aid_symmcrypt_index(CURRENT_SYMMCRYPT)->iv_size;
}

int
crypto_symmenc_generate(
    unsigned char *key,
    size_t keysize)
{
    int state = 0;
    aid_symmkeys_key_t enckey;

    if ((state = aid_symmkeys_generate(
        CURRENT_SYMM_ENCKEY,
        &crypto_rand,
        rng_ctx,
        &enckey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to generate new symmetric encryption key");
        goto out;
    }

    if ((state = aid_symmkeys_to_binary(
        (aid_symmkeys_key_t const *) enckey,
        key,
        keysize)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to convert encryption key to binary");
    }

    aid_symmkeys_cleanup(enckey);

out:
    return state;
}

size_t
crypto_cipherlen(
    size_t plainlen)
{
    return aid_symmcrypt_index(CURRENT_SYMMCRYPT)->cipherlen(plainlen) + 1;
}


size_t
crypto_plainlen(
    size_t cipherlen)
{
    return aid_symmcrypt_index(CURRENT_SYMMCRYPT)->plainlen(cipherlen - 1);
}


int
crypto_encrypt(
    unsigned char const *data,
    size_t dsize,
    unsigned char *cipherbuf,
    size_t cipherlen,
    unsigned char const *iv,
    size_t ivsize,
    unsigned char const *key,
    size_t keysize)
{
    int state = 0;
    aid_symmkeys_key_t enckey;

    if ((state = aid_symmkeys_from_binary(
        key,
        keysize,
        &enckey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize encryption key");
        goto out;
    }

    cipherbuf[0] = (unsigned char)CURRENT_SYMMCRYPT;

    if ((state = aid_symmcrypt_encrypt(
        CURRENT_SYMMCRYPT,
        data,
        dsize,
        cipherbuf + 1,
        cipherlen - 1,
        iv,
        ivsize,
        (aid_symmkeys_key_t const *)&key)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to encrypt data with encryption");
    }

    aid_symmkeys_cleanup(&enckey);

out:
    return state;
}


int
crypto_decrypt(
    unsigned char const *data,
    size_t dsize,
    unsigned char *plainbuf,
    size_t plainlen,
    unsigned char const *iv,
    size_t ivsize,
    unsigned char const *key,
    size_t keysize);


/** asymmetric encryption crypto */
size_t
crypto_asymenc_size_priv(void);

size_t
crypto_asymenc_size_pub(void);

int
crypto_asymenc_generate(
    unsigned char *priv,
    size_t privsize,
    unsigned char *pub,
    size_t pubsize);

int
crypto_asymenc_public(
    unsigned char const *priv,
    size_t privsize,
    unsigned char *pub,
    size_t pubsize);

/** kdf and encryption */
int
crypto_kdf(
    unsigned char const *priv,
    size_t privsize,
    unsigned char const *pub,
    size_t pubsize,
    unsigned char *key,
    size_t keysize);

int
crypto_asym_encrypt(
    unsigned char const *data,
    size_t dsize,
    unsigned char *cipherbuf,
    size_t cipherlen,
    unsigned char const *iv,
    size_t ivlen,
    unsigned char const *priv,
    size_t privsize,
    unsigned char const *pub,
    size_t pubsize);

int
crypto_asym_decrypt(
    unsigned char const *data,
    size_t dsize,
    unsigned char *plainbuf,
    size_t plainlen,
    unsigned char const *iv,
    size_t ivlen,
    unsigned char const *priv,
    size_t privsize,
    unsigned char const *pub,
    size_t pubsize);


/** asymmetric signing crypto */
size_t
crypto_asymsign_size_sig(void);

size_t
crypto_asymsign_size_priv(void);

size_t
crypto_asymsign_size_pub(void);

int
crypto_asymsign_generate(
    unsigned char *priv,
    size_t privsize,
    unsigned char *pub,
    size_t pubsize);

int
crypto_asymsign_public(
    unsigned char const *priv,
    size_t privsize,
    unsigned char *pub,
    size_t pubsize);

int
crypto_sign(
    unsigned char const *data,
    size_t dsize,
    unsigned char *sigbuf,
    size_t sigsize,
    unsigned char const *priv,
    size_t privsize);

// 0 verified successfully
// 1 failed to verify
int
crypto_verify(
    unsigned char const *data,
    size_t dsize,
    unsigned char const *sigbuf,
    size_t sigsize,
    unsigned char const *pub,
    size_t pub);



