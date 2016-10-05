#include "aid/common/crypto.h"

#include <stdlib.h>

#include "aid/core/error.h"
#include "aid/core/log.h"
#include "aid/core/utils.h"
#include "aid/crypto/hash.h"
#include "aid/crypto/kdf.h"
#include "aid/crypto/asymkeys.h"
#include "aid/crypto/asymsign.h"
#include "aid/crypto/symmcrypt.h"
#include "aid/crypto/symmkeys.h"

__thread void *rng_ctx;


int
crypto_rng_init(void) {
    rng_ctx = malloc(1);

    return 0;
}


int
crypto_rand(
    void *ctx,
    unsigned char *buf,
    size_t bufsize)
{
    int state = 0;

    if (!ctx || !buf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!bufsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if ((state = aid_utils_rand(
        ctx,
        buf,
        bufsize)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to generate random values");
        goto out;
    }

out:
    return state;
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
    int state = 0;
    aid_hash_index_t const *index;

    if (!data || !hashbuf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(index = aid_hash_index(CURRENT_HASH))) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (bufsize != (index->hash_size + 1)) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    hashbuf[0] = (unsigned char)CURRENT_HASH;

    if ((state = aid_hash_digest(
        CURRENT_HASH,
        data,
        dsize,
        hashbuf + 1,
        bufsize - 1)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to calculate cryptographic hash");
        goto out;
    }

out:
    return state;
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
    int state = 0;
    aid_hash_index_t const *index;
    unsigned char type;

    if (!data || !hashbuf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (!(index = aid_hash_index(CURRENT_HASH))) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (bufsize != (index->hash_size + 1)) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    type = hashbuf[0]; 

    if ((state = aid_hash_verify(
        type,
        data,
        dsize,
        hashbuf + 1,
        bufsize - 1)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to verify cryptographic hash");
        goto out;
    }

out:
    return state;
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

    if (!key) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

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
        (aid_symmkeys_key_t const *) &enckey,
        key,
        keysize)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to convert encryption key to binary");
    }

    aid_symmkeys_cleanup(&enckey);

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

    if (!data || !cipherbuf || !iv || !key) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (cipherlen < crypto_cipherlen(dsize)) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (ivsize != crypto_iv_size()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (keysize != crypto_key_size()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

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
        (aid_symmkeys_key_t const *)&enckey)) < 0)
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
    size_t keysize)
{
    int state = 0;
    aid_symmkeys_key_t enckey;

    if (!data || !plainbuf || !iv || !key) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (plainlen != crypto_plainlen(dsize)) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (ivsize != crypto_iv_size()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (keysize != crypto_key_size()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (aid_symmcrypt_index(data[0])->key_type != key[0]) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "Key is not of correct type for ciphertext");
        goto out;
    }

    if ((state = aid_symmkeys_from_binary(
        key,
        keysize,
        &enckey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize encryption key");
        goto out;
    }

    if ((state = aid_symmcrypt_decrypt(
        data[0],
        data + 1,
        dsize - 1,
        plainbuf,
        plainlen,
        iv,
        ivsize,
        (aid_symmkeys_key_t const *)&enckey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to decrypt data with encryption");
    }

    aid_symmkeys_cleanup(&enckey);

out:
    return state;
}


/** asymmetric encryption crypto */
size_t
crypto_asymenc_size_priv(void) {
    return aid_asymkeys_index(CURRENT_ASYM_ENCKEY)->priv_size + 1;
}


size_t
crypto_asymenc_size_pub(void) {
    return aid_asymkeys_index(CURRENT_ASYM_ENCKEY)->pub_size + 1;
}

int
crypto_asymenc_generate(
    unsigned char *priv,
    size_t privsize,
    unsigned char *pub,
    size_t pubsize)
{
    aid_asymkeys_private_t privkey;
    aid_asymkeys_public_t pubkey;
    int state = 0;

    if (!priv || !pub) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (privsize != crypto_asymenc_size_priv()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (pubsize != crypto_asymenc_size_pub()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if ((state = aid_asymkeys_generate(
        CURRENT_ASYM_ENCKEY,
        &crypto_rand,
        rng_ctx,
        &privkey,
        &pubkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to encryption keypair");
        goto out;
    }

    if ((state = aid_asymkeys_to_binary_priv(
        (aid_asymkeys_private_t const *) &privkey,
        priv,
        privsize)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize private key");
        goto cleanup_keys;
    }

    if ((state = aid_asymkeys_to_binary_pub(
        (aid_asymkeys_public_t const *) &pubkey,
        pub,
        pubsize)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize public key");
        goto cleanup_keys;
    }

cleanup_keys:
    aid_asymkeys_cleanup_priv(&privkey);
    aid_asymkeys_cleanup_pub(&pubkey);
out:
    return state;
}

int
crypto_asymenc_public(
    unsigned char const *priv,
    size_t privsize,
    unsigned char *pub,
    size_t pubsize)
{
    aid_asymkeys_private_t privkey;
    aid_asymkeys_public_t pubkey;
    int state;

    if (!priv || !pub) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (privsize != crypto_asymenc_size_priv()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (pubsize != crypto_asymenc_size_pub()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if ((state = aid_asymkeys_from_binary_priv(
        priv,
        privsize,
        &privkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize private key");
        goto out;
    }

    if ((state = aid_asymkeys_public(
        (aid_asymkeys_private_t const *) &privkey,
        &pubkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to calculate public key");
        goto cleanup_priv;
    }

    if ((state = aid_asymkeys_to_binary_pub(
        (aid_asymkeys_public_t const *) &pubkey,
        pub,
        pubsize)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to serialize public key");
    }

    aid_asymkeys_cleanup_pub(&pubkey);

cleanup_priv:
    aid_asymkeys_cleanup_priv(&privkey);
out:
    return state;
}

/** kdf and encryption */
int
crypto_kdf(
    unsigned char const *priv,
    size_t privsize,
    unsigned char const *pub,
    size_t pubsize,
    unsigned char *key,
    size_t keysize)
{
    aid_asymkeys_private_t privkey;
    aid_asymkeys_public_t pubkey;
    aid_symmkeys_key_t enckey;
    int state = 0;

    if (!priv || !pub || !key) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (privsize != crypto_asymenc_size_priv()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (pubsize != crypto_asymenc_size_pub()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (keysize < crypto_key_size()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "Buffer provided for the key is of insufficient size");
        goto out;
    }

    if ((state = aid_asymkeys_from_binary_priv(
        priv,
        privsize,
        &privkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize private key");
        goto out;
    }

    if ((state = aid_asymkeys_from_binary_pub(
        pub,
        pubsize,
        &pubkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize public key");
        goto cleanup_privkey;
    }

    if ((state = aid_kdf_compute(
        CURRENT_KDF,
        (aid_asymkeys_private_t const *) &privkey,
        (aid_asymkeys_public_t const *) &pubkey,
        &enckey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to compute encryption key via kdf");
        goto cleanup_pubkey;
    }

    if ((state = aid_symmkeys_to_binary(
        (aid_symmkeys_key_t const *) &enckey,
        key,
        keysize)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to serialize encryption key");
        goto cleanup_enckey;
    }

cleanup_enckey:
    aid_symmkeys_cleanup(&enckey);
cleanup_pubkey:
    aid_asymkeys_cleanup_pub(&pubkey);
cleanup_privkey:
    aid_asymkeys_cleanup_priv(&privkey);
out:
    return state;
}

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
    size_t pubsize)
{
    aid_asymkeys_private_t privkey;
    aid_asymkeys_public_t pubkey;
    aid_symmkeys_key_t enckey;    
    int state = 0;

    if (!data || !cipherbuf || !iv ||  !priv || !pub) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (cipherlen != crypto_cipherlen(dsize)) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (ivlen != crypto_iv_size()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (privsize != crypto_asymenc_size_priv()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (pubsize != crypto_asymenc_size_pub()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if ((state = aid_asymkeys_from_binary_priv(
        priv,
        privsize,
        &privkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize private key");
        goto out;
    }

    if ((state = aid_asymkeys_from_binary_pub(
        pub,
        pubsize,
        &pubkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize public key");
        goto cleanup_privkey;
    }

    if ((state = aid_kdf_compute(
        CURRENT_KDF,
        (aid_asymkeys_private_t const *) &privkey,
        (aid_asymkeys_public_t const *) &pubkey,
        &enckey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to compute encryption key via kdf");
        goto cleanup_pubkey;
    }

    cipherbuf[0] = (unsigned char) CURRENT_SYMMCRYPT;

    if ((state = aid_symmcrypt_encrypt(
        CURRENT_SYMMCRYPT,
        data,
        dsize,
        cipherbuf + 1,
        cipherlen - 1,
        iv,
        ivlen,
        (aid_symmkeys_key_t const *) &enckey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to encrypt data");
        goto cleanup_enckey;
    }

cleanup_enckey:
    aid_symmkeys_cleanup(&enckey);
cleanup_pubkey:
    aid_asymkeys_cleanup_pub(&pubkey);
cleanup_privkey:
    aid_asymkeys_cleanup_priv(&privkey);
out:
    return state;
}

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
    size_t pubsize)
{
    aid_asymkeys_private_t privkey;
    aid_asymkeys_public_t pubkey;
    aid_symmkeys_key_t enckey;    
    int state = 0;

    if (!data || !plainbuf || !iv ||  !priv || !pub) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (dsize <= 1) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (plainlen != crypto_plainlen(dsize)) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (ivlen != crypto_iv_size()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (privsize != crypto_asymenc_size_priv()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (pubsize != crypto_asymenc_size_pub()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if ((state = aid_asymkeys_from_binary_priv(
        priv,
        privsize,
        &privkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize private key");
        goto out;
    }

    if ((state = aid_asymkeys_from_binary_pub(
        pub,
        pubsize,
        &pubkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize public key");
        goto cleanup_privkey;
    }

    if ((state = aid_kdf_compute(
        CURRENT_KDF,
        (aid_asymkeys_private_t const *) &privkey,
        (aid_asymkeys_public_t const *) &pubkey,
        &enckey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to compute encryption key via kdf");
        goto cleanup_pubkey;
    }

    if ((state = aid_symmcrypt_decrypt(
        (aid_symmcrypt_t) data[0],
        data,
        dsize,
        plainbuf,
        plainlen,
        iv,
        ivlen,
        (aid_symmkeys_key_t const *) &enckey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to decrypt data");
        goto cleanup_enckey;
    }

cleanup_enckey:
    aid_symmkeys_cleanup(&enckey);
cleanup_pubkey:
    aid_asymkeys_cleanup_pub(&pubkey);
cleanup_privkey:
    aid_asymkeys_cleanup_priv(&privkey);
out:
    return state;

}


/** asymmetric signing crypto */
size_t
crypto_asymsign_size_sig(void) {
    return aid_asymsign_index(CURRENT_ASYMSIGN)->sig_size + 1;
}


size_t
crypto_asymsign_size_priv(void) {
    return aid_asymkeys_index(aid_asymsign_index(CURRENT_ASYM_SIGNKEY)->key_type)->priv_size + 1;
}


size_t
crypto_asymsign_size_pub(void) {
    return aid_asymkeys_index(aid_asymsign_index(CURRENT_ASYM_SIGNKEY)->key_type)->pub_size + 1;
}


int
crypto_asymsign_generate(
    unsigned char *priv,
    size_t privsize,
    unsigned char *pub,
    size_t pubsize)
{
    aid_asymkeys_private_t privkey;
    aid_asymkeys_public_t pubkey;
    int state = 0;

    if (!priv || !pub) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (privsize != crypto_asymsign_size_priv()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (pubsize != crypto_asymsign_size_pub()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if ((state = aid_asymkeys_generate(
        CURRENT_ASYM_SIGNKEY,
        &crypto_rand,
        rng_ctx,
        &privkey,
        &pubkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to encryption keypair");
        goto out;
    }

    if ((state = aid_asymkeys_to_binary_priv(
        (aid_asymkeys_private_t const *) &privkey,
        priv,
        privsize)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize private key");
        goto cleanup_keys;
    }

    if ((state = aid_asymkeys_to_binary_pub(
        (aid_asymkeys_public_t const *) &pubkey,
        pub,
        pubsize)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize public key");
        goto cleanup_keys;
    }

cleanup_keys:
    aid_asymkeys_cleanup_priv(&privkey);
    aid_asymkeys_cleanup_pub(&pubkey);
out:
    return state;
}


int
crypto_asymsign_public(
    unsigned char const *priv,
    size_t privsize,
    unsigned char *pub,
    size_t pubsize)
{
    aid_asymkeys_private_t privkey;
    aid_asymkeys_public_t pubkey;
    int state;

    if (!priv || !pub) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (privsize != crypto_asymsign_size_priv()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (pubsize != crypto_asymsign_size_pub()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if ((state = aid_asymkeys_from_binary_priv(
        priv,
        privsize,
        &privkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize private key");
        goto out;
    }

    if ((state = aid_asymkeys_public(
        (aid_asymkeys_private_t const *) &privkey,
        &pubkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to calculate public key");
        goto cleanup_priv;
    }

    if ((state = aid_asymkeys_to_binary_pub(
        (aid_asymkeys_public_t const *) &pubkey,
        pub,
        pubsize)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to serialize public key");
    }

    aid_asymkeys_cleanup_pub(&pubkey);

cleanup_priv:
    aid_asymkeys_cleanup_priv(&privkey);
out:
    return state;
}


int
crypto_sign(
    unsigned char const *data,
    size_t dsize,
    unsigned char *sigbuf,
    size_t sigsize,
    unsigned char const *priv,
    size_t privsize)
{
    aid_asymkeys_private_t privkey;
    int state = 0;

    if (!data || !sigbuf || !priv) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (privsize != crypto_asymsign_size_priv()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }
    
    if (sigsize != crypto_asymsign_size_sig()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if ((state = aid_asymkeys_from_binary_priv(
        priv,
        privsize,
        &privkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize private key");
        goto out;
    }

    sigbuf[0] = CURRENT_ASYMSIGN;

    if ((state = aid_asymsign_sign(
        CURRENT_ASYMSIGN,
        data,
        dsize,
        sigbuf + 1,
        sigsize - 1,
        (aid_asymkeys_private_t const *) &privkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to compute asymmetric signature");
    }

    aid_asymkeys_cleanup_priv(&privkey);
out:
    return state;
}

// 0 verified successfully
// 1 failed to verify
int
crypto_verify(
    unsigned char const *data,
    size_t dsize,
    unsigned char const *sigbuf,
    size_t sigsize,
    unsigned char const *pub,
    size_t pubsize)
{
    aid_asymkeys_public_t pubkey;
    int state = 0;

    if (!data || !sigbuf || !pub) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!dsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (pubsize != crypto_asymsign_size_pub()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }
    
    if (sigsize != crypto_asymsign_size_sig()) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    if (pub[0] != aid_asymsign_index(sigbuf[0])->key_type) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, "Can not verify signature because key-type does not match signing algorithm");
        goto out;
    }

    if ((state = aid_asymkeys_from_binary_pub(
        pub,
        pubsize,
        &pubkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to deserialize public key");
        goto out;
    }

    if ((state = aid_asymsign_verify(
        sigbuf[0],
        data,
        dsize,
        sigbuf + 1,
        sigsize - 1,
        (aid_asymkeys_public_t const *) &pubkey)) < 0)
    {
        AID_LOG_ERROR(AID_ERR_RETURN, "Failed to compute asymmetric signature");
    }

    aid_asymkeys_cleanup_pub(&pubkey);
out:
    return state;
}
