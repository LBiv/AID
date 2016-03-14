#ifndef AID_CRYPTO_SYMMCRYPT
#define AID_CRYPTO_SYMMCRYPT

#include "aid/crypto/symmkeys.h"

//Must remain less than 256
#define AID_SYMMCRYPT_NUM 1


typedef enum {
    AID_SYMMCRYPT_XSALSA20 = 1
} aid_symmcrypt_t;


aid_symmcrypt_index_t const *
aid_symmcrypt_index(
    aid_symmcrypt_t type);

int
aid_symmcrypt_encrypt(
    aid_symmcrypt_t type,
    unsigned char const *data,
    size_t dsize,
    unsigned char *cipherbuf,
    size_t bufsize,
    unsigned char const *iv,
    size_t ivsize,
    aid_symmkeys_key_t const *key);

int
aid_symmcrypt_decrypt(
    aid_symmcrypt_t type,
    unsigned char const *data,
    size_t dsize,
    unsigned char *plainbuf,
    size_t bufsize,
    unsigned char const *iv,
    size_t ivsize,
    aid_symmkeys_key_t const *key);

#endif
