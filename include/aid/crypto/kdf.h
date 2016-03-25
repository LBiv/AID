#ifndef AID_CRYPTO_KDF
#define AID_CRYPTO_KDF

#include "aid/crypto/general.h"
#include "aid/crypto/asymkeys.h"
#include "aid/crypto/symmkeys.h"
#include "aid/crypto/symmcrypt.h"

//Must remain less than 256
#define AID_KDF_NUM 1

typedef enum {
    AID_KDF_CURVE25519_ECDH_XSALSA20 = 1
} aid_kdf_t;

typedef struct {
    aid_asymkeys_t input_type;
    aid_symmkeys_t key_type;
    char const *name;
    kdf_compute_t compute;
} aid_kdf_index_t;


aid_kdf_index_t const *
aid_kdf_index(
    aid_kdf_t type);

int
aid_kdf_compute(
    aid_kdf_t type,
    aid_asymkeys_private_t const *priv,
    aid_asymkeys_public_t const *pub,
    aid_symmkeys_key_t *key);

//TODO
// Add function aid_kdf_sign that generates an symmetric signing (MAC) key.


#endif
