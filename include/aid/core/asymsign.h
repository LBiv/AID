#ifndef AID_CORE_ASYMSIGN
#define AID_CORE_ASYMSIGN

#include "aid/core/asymkeys.h"

//Must remain less than 256
#define AID_ASYMSIGN_ALGO_NUM 1

typedef struct {
    aid_asymkeys_algo_t key_type;
    size_t sig_size;
    char const *name;
} aid_asymsign_index_t;

extern aid_asymsign_index_t aid_asymsign_index[AID_ASYMSIGN_ALGO_NUM];

typedef enum {
    AID_ASYMSIGN_EDDSA = 1
} aid_asymsign_algo_t;


int
aid_signing_sign(
    aid_asymsign_algo_t type,
    unsigned char const *data,
    size_t dsize,
    aid_asymkeys_private_t const *key,
    unsigned char *sigbuf);

int
aid_signing_verify(
    aid_asymsign_algo_t type,
    unsigned char const *data,
    size_t dsize,
    unsigned char const *sigbuf,
    size_t bufsize,
    aid_asymkeys_public_t const *key);



#endif
