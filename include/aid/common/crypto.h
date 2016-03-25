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

/**
#define CURRENT_RNG_FUNC
#define CURRENT_RNG_CTX
*/

extern char *rng_ctx;

int
aid_crypto_rng(
    void *ctx,
    unsigned char *buf,
    size_t bufsize);


int
aid_crypto_generate_asymenc(
    aid_asymkeys_public_t *pub,
    aid_asymkeys_private_t *priv);


int
aid_crypto_generate_asymsign(
    aid_asymkeys_public_t *pub,
    aid_asymkeys_private_t *priv);


int
aid_crypto_hash(
    unsigned char const *data,
    size_t dsize,
    unsigned char *hashbuf,
    size_t hashsize);


int
aid_crypto_kdf(
    aid_asymkeys_public_t const *pub,
    aid_asymkeys_private_t const *priv,
    aid_symmkeys_key_t *key);


int
aid_crypto_encrypt(
    aid_symmkeys
    aid_symmkeys_key const *key,
    


    



#endif
