#ifndef AID_COMMON_TOKEN
#define AID_COMMON_TOKEN

typedef struct {
    aid_signkey_public_t *signing;
    aid_enckey_public_t *encryption;
} aid_identity_token_t;


int
aid_token_format(
    aid_identity_token_t const *token,
    unsigned char **out,
    size_t *outsize);

int
aid_token_parse(
    unsigned char const *in,
    size_t insize,
    aid_provider_token_t *token);

int
aid_token_verify(
    unsigned char const *in,
    size_t insize,
    aid_provider_token_t *previous);


#endif
