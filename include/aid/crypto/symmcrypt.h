#ifndef AID_CRYPTO_SYMMCRYPT
#define AID_CRYPTO_SYMMCRYPT

#include "aid/core/symmkeys.h"

//Must remain less than 256
#define AID_SYMMCRYPT_NUM 1

typedef struct {
    aid_symmkeys_t key_type;
    size_t iv_size;
//TODO
//For ciphers that include a signature (such as AES-GCM add MAC key information
//here
    char const *name;
} aid_symmcrypt_index_t;

typedef enum {
    AID_SYMMCRYPT_AES256_CBC = 1
} aid_symmcrypt_t;

typedef struct {
    aid_symmcrypt_t type;
    unsigned char *iv;
} aid_symmcrypt_iv_t;
//TODO
//For ciphers that include a signature (such as AES-GCM add a MAC key struct
//here

aid_symmcrypt_index_t const *
aid_symmcrypt_index(
    aid_symmcrypt_t type);

int
aid_symmetric_encrypt(
    aid_symmcrypt_t type,
    unsigned char const *data,
    size_t dsize,
    aid_symmetric_t const *key,
    unsigned char *cipherbuf);

int
aid_symmetric_decrypt(
    aid_symmcrypt_t type,
    unsigned char const *data,
    size_t dsize,
    aid_symmetric_t const *key,
    unsigned char *plainbuf);

#endif
