#include "aid/crypto/kdf.h"

#include "tweetnacl.h"

#include "aid/core/error.h"
#include "aid/core.log.h"

typedef int (*kdf_crypt_t)(
    unsigned char const *,
    unsigned char const *,



int
aid_kdf_crypt(
    aid_kdf_t type

