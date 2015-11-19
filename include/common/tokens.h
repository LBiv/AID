typedef struct {
    signkey_t *signing;
    enckey_t *encryption;
    signkey_t *auxiliary;    
} provider_token_t;

typedef struct {
    signkey_t *signing;
    enckey_t *encryption;
} user_token_t;
