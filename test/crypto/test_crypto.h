#ifndef AID_COMMON_CRYPTO_H
#define AID_COMMON_CRYPTO_H

#include <check.h>
#include <stdlib.h>
#include <string.h>

Suite *
asymkeys_suite(void);

Suite *
asymsign_suite(void);

Suite *
hash_suite(void);

Suite *
kdf_suite(void);

Suite *
symmcrypt_suite(void);

Suite *
symmkeys_suite(void);

#endif
