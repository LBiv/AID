#ifndef AID_CRYPTO_ASYMKEYS
#define AID_CRYPTO_ASYMKEYS

#include "aid/crypto/general.h"

//Must remain less than 256
#define AID_ASYMKEYS_NUM 2

typedef enum {
    AID_ASYMKEYS_ED25519 = 1,
    AID_ASYMKEYS_X25519 = 2
} aid_asymkeys_t;

typedef struct {
    aid_asymkeys_t type;
    unsigned char *key; 
} aid_asymkeys_private_t;

typedef struct {
    aid_asymkeys_t type;
    unsigned char *key; 
} aid_asymkeys_public_t;

typedef struct {
    size_t priv_size;
    size_t pub_size;
    char const *name;
    asymkeys_generate_t generate;
    asymkeys_public_t pub;
} aid_asymkeys_index_t;


aid_asymkeys_index_t const *
aid_asymkeys_index(
    aid_asymkeys_t type);

int
aid_asymkeys_generate(
    aid_asymkeys_t type,
    rng_function_t f_rng,
    void *p_rng,
    aid_asymkeys_private_t *priv,
    aid_asymkeys_public_t *pub);

int
aid_asymkeys_public(
    aid_asymkeys_private_t const *priv,
    aid_asymkeys_public_t *pub);

void
aid_asymkeys_cleanup_priv(
    aid_asymkeys_private_t *priv);

void
aid_asymkeys_cleanup_pub(
    aid_asymkeys_public_t *pub);


#endif
