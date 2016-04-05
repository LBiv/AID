#ifndef AID_COMMON_CRYPTO_H
#define AID_COMMON_CRYPTO_H


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

/** RNG crypto **/
extern __thread void *rng_ctx;

int
crypto_rng_init(void);


int
crypto_rand(
    void *ctx,
    unsigned char *buf,
    size_t bufsize);


/** cryptographic hash **/
size_t
crypto_hash_size(void);

int
crypto_hash_digest(
    unsigned char const *data,
    size_t dsize,
    unsigned char *hashbuf,
    size_t bufsize);

// 0 if verified successfully
// 1 if failed to verify
int
crypto_hash_verify(
    unsigned char const *data,
    size_t dsize,
    unsigned char const *hashbuf,
    size_t bufsize);


/** symmetric encryption crypto */
size_t
crypto_key_size(void);

size_t
crypto_iv_size(void);

int
crypto_symmenc_generate(
    unsigned char *key,
    size_t keysize);

size_t
crypto_cipherlen(
    size_t plainlen);


size_t
crypto_plainlen(
    size_t cipherlen);

int
crypto_encrypt(
    unsigned char const *data,
    size_t dsize,
    unsigned char *cipherbuf,
    size_t cipherlen,
    unsigned char const *iv,
    size_t ivsize,
    unsigned char const *key,
    size_t keysize);

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


#endif
