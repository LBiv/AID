#ifndef AID_CRYPTO_HASH
#define AID_CRYPTO_HASH

#define AID_HASH_NUM 1

typedef enum {
    AID_HASH_SHA512 = 1
} aid_hash_t;


aid_hash_index_t const *
aid_hash_index(
    aid_hash_t type);

int
aid_hash_digest(
    aid_hash_t type,
    unsigned char const *data,
    size_t dsize,
    unsigned char *hashbuf);

// 0 is valid hash
// 1 is invalid hash
int
aid_hash_verify(
    aid_hash_t type,
    unsigned char const *data,
    size_t dsize,
    unsigned char const *hashbuf,
    size_t hashsize);



#endif
