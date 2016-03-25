#ifndef AID_COMMON_CRYPTO_H
#define AID_COMMON_CRYPTO_H

#include "aid/crypto/asymkeys.h"
#include "aid/crypto/asymsign.h"
#include "aid/crypto/symmkeys.h"
#include "aid/crypto/symmcrypt.h"
#include "aid/crypto/hash.h"
#include "aid/crypto/kdf.h"
#include "aid/core/utils.h"


#define CURRENT_HASH AID_HASH_SHA512
#define CURRENT_KDF AID_KDF_ECDH_XSALSA20
#define CURRENT_SYMMCRYPT AID_SYMMCRYPT_XSALSA20
#define CURRENT_ASYMSIGN AID_ASYMSIGN_EdDSA
#define CURRENT_SYMM_ENCKEY AID_SYMMKEYS_XSALSA20
#define CURRENT_ASYM_ENCKEY AID_ASYMKEYS_X25519
#define CURRENT_ASYM_SIGNKEY AID_ASYMKEYS_ED25519

/**
#define CURRENT_RNG_FUNC
#define CURRENT_RNG_CTX
*/

typedef enckey_pub_t aid_asymkeys_public_t;
typedef enckey_priv_t aid_asymkeys_private_t;

typedef signkey_pub_t aid_asymkeys_public_t;
typedef signkey_priv_t aid_asymkeys_private_t;

typedef enckey_symm_t aid_symmkeys_key_t;

extern char *rng_ctx;


int
crypto_rng(
    void *ctx,
    unsigned char *buf,
    size_t bufsize);


int
crypto_generate_asymenc(
    enckey_pub_t *pub,
    enckey_priv_t *priv);


int
crypto_generate_asymsign(
    signkey_pub_t *pub,
    signkey_priv_t *priv);


int
crypto_generate_symmenc(
    enckey_symm_t *key);


int
crypto_hash(
    unsigned char const *data,
    size_t dsize,
    unsigned char *hashbuf,
    size_t hashsize);


int
crypto_kdf(
    enckey_pub_t const *pub,
    enckey_priv_t const *priv,
    enckey_symm_t *key);


int
crypto_cipherlen(
    size_t plainlen,
    size_t *cipherlen);


int
crypto_plainlen(
    size_t cipherlen,
    size_t *plainlen);


int
crypto_encrypt(
    unsigned char const *data,
    size_t dsize,
    unsigned char *cipherbuf,
    size_t cipherlen,
    unsigned char const *iv,
    size_t ivlen,
    enckey_symm_t const *key);


int
crypto_decrypt(
    unsigned char const *data,
    size_t dsize,
    unsigned char *plainbuf,
    size_t plainlen,
    unsigned char const *iv,
    size_t ivlen,
    enckey_symm_t const *key);


int
crypto_asym_encrypt(
    unsigned char const *data,
    size_t dsize,
    unsigned char *cipherbuf,
    size_t cipherlen,
    unsigned char const *iv,
    size_t ivlen,
    enckey_pub_t const *pub,
    enckey_priv_t const *priv);


int
crypto_asym_decrypt(
    unsigned char const *data,
    size_t dsize,
    unsigned char *plainbuf,
    size_t plainlen,
    unsigned char const *iv,
    size_t ivlen,
    enckey_pub_t const *pub,
    enckey_priv_t const *priv);


int
crypto_asym_sign(
    unsigned char const *data,
    size_t dsize,
    unsigned char *sigbuf,
    size_t sigsize,
    signkey_priv_t const *priv);


int
crypto_asym_verify(
    unsigned char const *data,
    size_t dsize,
    unsigned char const *sigbuf,
    size_t sigsize,
    signkey_pub_t const *pub);


#endif
