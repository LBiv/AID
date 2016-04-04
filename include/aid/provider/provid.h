#ifndef AID_PROVIDER_PROVID_H
#define AID_PROVIDER_PROVID_H

#include "aid/crypto/asymkeys.h"

typedef struct {
    char *domain;   // Domain for which this identification token is created.
    char *past_domain; // Domain for which the previous identification token was created.
    aid_asymkeys_public_t *signkey; // new public signing key.
    aid_asymkeys_public_t *enckey; // new public encryption key.
    unsigned char *rotsig; // buffer with rotational signature.
    size_t rotsigsize;  // size of rotational signature buffer.
    unsigned char *idsig; // buffer with current token signature.
    size_t idsigsize; // size of token signature buffer.
} aid_provid_token_t;


int
aid_provid_token_create(
    char const *domain,
    char const *past_domain,
    aid_asymkeys_public_t const *signkey,
    aid_asymkeys_public_t const *enckey,
    aid_asymkeys_private_t const *newprivkey,
    aid_asymkeys_private_t const *oldprivkey
    aid_provid_token_t *token);


int // 0 if successfully verified, 1 if failed verification
aid_provid_token_verify(
    aid_provid_token_t const *token,
    char const *domain,
    char const *past_domain,
    aid_asymkeys_public_t const *oldsignkey); 


#endif
