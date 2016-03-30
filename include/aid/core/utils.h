#ifndef AID_CORE_UTILS
#define AID_CORE_UTILS

#include <stddef.h>

/**secure memory wipe */
int
aid_utils_wipe(
    unsigned char *buf,
    size_t bufsize);

/**simple rand */
int
aid_utils_rand(
    void *ctx,
    unsigned char *buf,
    size_t bufsize);

/** encoding **/
int
aid_utils_b64url_encode_size(
    size_t insize,
    size_t *outsize);

int
aid_utils_b64url_decode_size(
    size_t insize,
    size_t *outsize);

int
aid_utils_b64url_encode(
    unsigned char const *data,
    size_t dsize,
    char *encbuf,
    size_t bufsize);

int 
aid_utils_b64url_decode(
    char const *data,
    size_t dsize,
    unsigned char *decbuf,
    size_t bufsize);

/** logging helper **/
char *
aid_utils_log_helper(
    char const *filename,
    char const *func,
    int line,
    int state,
    char const *info);


#endif 
