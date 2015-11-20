#ifndef AID_COMMON_TOKENS
#define AID_COMMON_TOKENS

typedef struct {
    aid_signkey_public_t *signing;
    aid_enckey_public_t *encryption;
    aid_signkey_public_t *auxiliary;    
} aid_provider_token_t;

typedef struct {
    aid_signkey_public_t *signing;
    aid_enckey_public_t *encryption;
} aid_user_token_t;


int
aid_token_provider_format(
    aid_provider_token_t const *token,
    unsigned char **out,
    size_t *outsize);

int
aid_token_provider_parse(
    unsigned char const *in,
    size_t insize,
    aid_provider_token_t *token);

int
aid_token_provider_verify(
    unsigned char const *in,
    size_t insize,
    aid_provider_token_t *previous);


int
aid_token_user_format(
    aid_user_token_t const *token,
    unsigned char **out,
    size_t *outsize);

int
aid_token_user_parse(
    unsigned char const *in,
    size_t insize,
    aid_user_token_t *token);

int
aid_token_user_parse(
    unsigned char const *in,
    size_t insize,
    aid_user_token_t *previous,
    aid_provider_token_t *provider);


#endif
