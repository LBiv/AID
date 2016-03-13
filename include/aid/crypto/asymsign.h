#ifndef AID_CRYPTO_ASYMSIGN
#define AID_CRYPTO_ASYMSIGN

#include "aid/crypto/asymkeys.h"

//Must remain less than 256
#define AID_ASYMSIGN_NUM 1

typedef struct {
    aid_asymkeys_t key_type;
    size_t sig_size;
    char const *name;
} aid_asymsign_index_t;

typedef enum {
    AID_ASYMSIGN_EDDSA = 1
} aid_asymsign_t;


aid_asymsign_index_t const *
aid_asymsign_index(
    aid_asymsign_t type);

int
aid_asymsign_sign(
    aid_asymsign_t type,
    unsigned char const *data,
    size_t dsize,
    unsigned char *sigbuf,
    size_t bufsize,
    aid_asymkeys_private_t const *key);

// 0 is valid signature
// 1 is invalid signature
int
aid_asymsign_verify(
    aid_asymsign_t type,
    unsigned char const *data,
    size_t dsize,
    unsigned char const *sigbuf,
    size_t bufsize,
    aid_asymkeys_public_t const *key);



#endif
