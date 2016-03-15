#ifndef AID_CRYPTO_SYMMCRYPT
#define AID_CRYPTO_SYMMCRYPT

#include "aid/crypto/general.h"
#include "aid/crypto/symmkeys.h"

//Must remain less than 256
#define AID_SYMMCRYPT_NUM 1


typedef enum {
    AID_SYMMCRYPT_XSALSA20 = 1
} aid_symmcrypt_t;

typedef struct {
    aid_symmkeys_t key_type;
    size_t iv_size;
//TODO
//For ciphers that include a signature (such as AES-GCM add MAC key information
//here
    char const *name;
    symmcrypt_encrypt_t encrypt;
    symmcrypt_decrypt_t decrypt;
    symmcrypt_cipherlen_t cipherlen;
    symmcrypt_plainlen_t plainlen;
} aid_symmcrypt_index_t;


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
