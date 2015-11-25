#ifndef AID_CORE_KDF
#define AID_CORE_KDF

#include "aid/core/asymkeys.h"
#include "aid/core/symmkeys.h"
#include "aid/core/symmcrypt.h"

//Must remain less than 256
#define AID_KDF_ALGO_NUM 1

//TODO
//Currently assumes that all KDFs take asymmetric keys as input and resolve to
//a symmetric key and an iv but this may need to be reworked.
typedef struct {
    aid_asymkeys_algo_t input_type;
    aid_symmkeys_algo_t key_type;
    aid_symmcrypt_algo_t crypt_type; //0 if no encryption key
    aid_symmsign_algo_t sign_type; //0 if no signing key
    char const *name;
} aid_kdf_index_t;

extern aid_kdf_index_t aid_kdf_index[AID_KDF_ALGO_NUM];

typedef enum {
    AID_KDF_CURVE25519_ECDH_HKDF_AES256 = 1
} aid_kdf_algo_t;


int
aid_kdf_crypt(
    aid_kdf_algo_t type,
    aid_asymkeys_private_t const *priv,
    aid_asymkeys_public_t const *pub,
    aid_symkeys_key_t *key,
    aid_symcrypt_key_t *iv);


#endif
