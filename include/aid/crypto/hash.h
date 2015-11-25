#ifndef AID_CORE_HASH
#define AID_CORE_HASH

#define AID_HASH_ALGO_NUM 1

typedef struct {
    size_t hash_size;
} aid_hash_index_t;

extern aid_hash_index_t aid_hash_index[AID_HASH_ALGO_NUM];

typedef enum {
    AID_HASH_SHA512 = 0x00
} aid_hash_algo_t;

int
aid_hash_digest(
    aid_hash_algo_t hash_algo,
    unsigned char const *data,
    size_t dsize,
    unsigned char *hashbuf);

int
aid_hash_verify(
    aid_hash_algo_t hash_algo,
    unsigned char const *data,
    size_t dsize,
    unsigned char const *hashbuf,
    size_t hashsize);



#endif
