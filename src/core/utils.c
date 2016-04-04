#include "aid/core/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aid/core/error.h"
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

/**
 *
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

*/

int
aid_utils_log_helper(
    char const *filename,
    char const *func,
    int line,
    int state,
    char const *info)
{
    char const
        *file_prompt = "In file: ",
        *func_prompt = ", function: ",
        *line_prompt = ", on line: ",
        *state_prompt = ". Error: ",
        *info_prompt = ". Info: ",
        *end = ".\n";
    int res = 0;
    size_t outsize = 0, printed = 0;;

    if (state > 0 || state <= -AID_ERR_NUM) {
        state = 0;
    }

    outsize =
        strlen(file_prompt) +
        strlen(filename) +
        strlen(func_prompt) +
        strlen(func) +
        strlen(line_prompt) +
        11 + // maximum int length
        strlen(state_prompt) + 
        strlen(aid_error_array[(unsigned int) ((-1) * state)]) +
        strlen(info_prompt) +
        strlen(info) +
        strlen(end);
        
    if (outsize > sizeof(aid_log_string)) {
        outsize = sizeof(aid_log_string);
    }

    memset(aid_log_string, 0, sizeof(aid_log_string));

    printed = snprintf(
        aid_log_string,
        outsize,
        "%s%s%s%s%s%d%s%s%s%s%s",
        file_prompt,
        filename,
        func_prompt,
        func,
        line_prompt,
        line,
        state_prompt,
        aid_error_array[(unsigned int) ((-1) * state)],
        info_prompt,
        info,
        end);

    res = !(printed <= outsize);

    return res;    
}

