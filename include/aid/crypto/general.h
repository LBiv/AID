#ifndef AID_CRYPTO_GENERAL
#define AID_CRYPTO_GENERAL

// RNG function type
typedef int (*rng_function_t)(
    void *,
    unsigned char *,
    size_t);

// asymmetric keys function types
typedef int (*asymkeys_generate_t)(
    rng_function_t,
    void *,
    unsigned char *,
    unsigned char *);

typedef int (*asymkeys_public_t)(
    unsigned char const *,
    unsigned char *);

// asymmetric signing function types
typedef int (*asymsign_sign_t)(
    unsigned char const *,
    size_t,
    unsigned char *,
    unsigned char const *);

typedef int (*asymsign_verify_t)(
    unsigned char const *,
    size_t,
    unsigned char const *,
    unsigned char const *);

// hash function types
typedef int (*hash_digest_t) (
    unsigned char const *,
    size_t,
    unsigned char *);

typedef int (*hash_verify_t) (
    unsigned char const *,
    size_t,
    unsigned char const *);

// kdf function types
typedef int (*kdf_compute_t)(
    unsigned char const *,
    unsigned char const *,
    unsigned char *);

// symmetric encryption function types
typedef int (*symmcrypt_encrypt_t)(
    unsigned char const *,
    size_t,
    unsigned char *,
    size_t,
    unsigned char const *,
    unsigned char const *);

typedef int (*symmcrypt_decrypt_t)(
    unsigned char const *,
    size_t,
    unsigned char *,
    size_t,
    unsigned char const *,
    unsigned char const *);

typedef size_t (*symmcrypt_cipherlen_t)(
    size_t);

typedef size_t (*symmcrypt_plainlen_t)(
    size_t);


#endif
