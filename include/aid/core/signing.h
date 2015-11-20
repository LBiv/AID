#ifndef AID_CORE_SIGNING
#define AID_CORE_SIGNING

#define AID_SIGNING_CURVES_NUM 1

typedef struct {
    size_t priv_size;
    size_t pub_size;
    size_t sig_size;
} aid_signing_index_t;

extern aid_signing_index_t aid_signing_index[AID_SIGNING_CURVES_NUM];

typedef enum {
    AID_SIGN_ED25519 = 0x00
} aid_signing_curve_t;

typedef struct {
    aid_signing_curve_t;
    unsigned char *key; 
} aid_signkey_private_t;

typedef struct {
    aid_signing_curve_t;
    unsigned char *key; 
} aid_signkey_public_t;

int
aid_signing_keypair(
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng,
    aid_signkey_private_t *priv,
    aid_signkey_public_t *pub);

int
aid_signing_cleanup_priv(
    aid_signkey_private_t *priv);

int
aid_signing_cleanup_pub(
    aid_signkey_public_t *pub);

int
aid_signing_public(
    aid_signkey_private_t const *priv,
    aid_signkey_public_t *pub);

int
aid_signing_sign(
    unsigned char const *data,
    size_t dsize,
    aid_signkey_private_t const *key,
    unsigned char *sigbuf);

int
aid_signing_verify(
    unsigned char const *data,
    size_t dsize,
    unsigned char const *sigbuf,
    size_t bufsize,
    aid_signkey_public_t const *key);



#endif
