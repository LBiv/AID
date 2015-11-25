#ifndef AID_CRYPTO_SYMMKEYS
#define AID_CRYPTO_SYMMKEYS

//Must remain less than 256
#define AID_SYMMKEYS_NUM 1

typedef struct {
    size_t key_size;
    char const *name;
} aid_symmkeys_index_t;

typedef enum {
    AID_SYMMKEYS_AES256 = 1
} aid_symmkeys_t;

typedef struct {
    aid_symmkeys_t type;
    unsigned char *key;
} aid_symmkeys_key_t;


aid_symmkeys_index_t const *
aid_symmkeys_index(
    aid_symmkeys_t type);

int
aid_symmkeys_generate(
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng,
    aid_symmkeys_key_t *key);

int
aid_symmkeys_cleanup(
    aid_symmkeys_key_t *key);


#endif
