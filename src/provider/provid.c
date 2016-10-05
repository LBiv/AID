#include "aid/provider/provid.h"


int
aid_provid_token_create(
    char const *domain,
    char const *past_domain,
    unsigned char const *signkey,
    size_t signkey_size;
    unsigned char const *enckey,
    size_t enckey_size;
    unsigned char const *newprivkey,
    size_t newprivkey_size;
    unsigned char const *oldprivkey
    size_t oldprivkey_size;
    aid_provid_token_t *token)
{
}


// 0 if successfully verified, 1 if failed verification
int
aid_provid_token_verify(
    aid_provid_token_t const *token,
    char const *domain,
    char const *past_domain,
    unsigned char const *oldsignkey
    size_t oldsignkey_size)
{

}


int
aid_provid_token_cleanup(
    aid_provid_token_t *token)
{

}
