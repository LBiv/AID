#include "aid/core/utils.h"

#include "aid/core/log.h"


int
aid_utils_wipe(
    unsigned char *buf,
    size_t bufzize)
{
    int state = 0;

    if (!buf) {
        state = AID_LOG_ERROR(AID_ERR_NULL_PTR, NULL);
        goto out;
    }

    if (!bufsize) {
        state = AID_LOG_ERROR(AID_ERR_BAD_PARAM, NULL);
        goto out;
    }

    memset(buf, 0xF0F0F0F0, bufsize);
    memset(buf, 0x0F0F0F0F, bufsize);
    memset(buf, 0x00000000, bufsize);

out:
    return state;
}
