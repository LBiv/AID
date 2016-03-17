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





#endif 
