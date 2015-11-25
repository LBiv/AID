#ifndef AID_CORE_SYMMKEYS
#define AID_CORE_SYMMKEYS

//Must remain less than 256
#define AID_SYMMKEYS_ALGO_NUM 1

typedef struct {
    size_t key_size;
    char const *name;
} aid_symmkeys_index_t;

extern aid_symmkeys_index_t aid_symmkeys_index[AID_SYMMKEYS_ALGO_NUM];

typedef enum {
    AID_SYMMKEYS_AES256 = 1
} aid_symmkeys_algo_t;

typedef struct {
    aid_symmkeys_algo_t type;
    unsigned char *key;
} aid_symmkeys_key_t;

int
aid_symmkeys_generate(
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng,
    aid_symmkeys_key_t *key);

int
aid_symmkeys_cleanup(
    aid_symmkeys_key_t *key);


#endif
