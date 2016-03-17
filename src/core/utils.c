#include "aid/core/utils.h"

#include <stdlib.h>
#include <string.h>

#include "aid/core/log.h"


int
aid_utils_wipe(
    unsigned char *buf,
    size_t bufsize)
{
    int state = 0;

    if (!buf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!bufsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    memset(buf, 0xFFFFFFFF, bufsize);
    memset(buf, 0x00000000, bufsize);
    memset(buf, 0xFFFFFFFF, bufsize);
    memset(buf, 0x00000000, bufsize);

out:
    return state;
}


int
aid_utils_rand(
    void *ctx,
    unsigned char *buf,
    size_t bufsize)
{
    int state = 0;

    if (!buf) {
        AID_LOG_ERROR(state = AID_ERR_NULL_PTR, NULL); 
        goto out;
    }

    if (!bufsize) {
        AID_LOG_ERROR(state = AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    for (size_t i = 0; i < bufsize; ++i) {
        buf[i] = (unsigned char)rand();
    }

out:
    return state;
}
