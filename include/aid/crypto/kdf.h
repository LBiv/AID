#ifndef AID_CRYPTO_KDF
#define AID_CRYPTO_KDF

#include "aid/crypto/asymkeys.h"
#include "aid/crypto/symmkeys.h"
#include "aid/crypto/symmcrypt.h"

//Must remain less than 256
#define AID_KDF_NUM 1

//TODO
//Currently assumes that all KDFs take asymmetric keys as input and resolve to
//a symmetric key and an iv but this may need to be reworked.
typedef struct {
    aid_asymkeys_t input_type;
    aid_symmkeys_t key_type;
    aid_symmcrypt_t crypt_type; //0 if no encryption key
    aid_symmsign_t sign_type; //0 if no signing key
    char const *name;
} aid_kdf_index_t;

typedef enum {
    AID_KDF_CURVE25519_ECDH_HKDF_AES256 = 1
} aid_kdf_t;

aid_kdf_index_t const *
aid_kdf_index(
    aid_kdf_t type);

int
aid_kdf_crypt(
    aid_kdf_t type,
    aid_asymkeys_private_t const *priv,
    aid_asymkeys_public_t const *pub,
    aid_symkeys_key_t *key,
    aid_symcrypt_key_t *iv);

//TODO
// Add function aid_kdf_sign that generates an symmetric signing (MAC) key.


#endif
