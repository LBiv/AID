#ifndef AID_CORE_LOG
#define AID_CORE_LOG

#include "aid/core/error.h"

#include <stddef.h>
#include <errno.h>

typedef void (*aid_log_func_t)(
    char const *,   // filename
    char const *,   // function name
    int,            // line number
    int,            // state/error
    char const *);  // specific log info

typedef struct {
    aid_log_func_t debug;
    aid_log_func_t info;
    aid_log_func_t error;
} aid_log_t;

extern __thread aid_log_t aid_log;
extern __thread char aid_log_string[512];

#define AID_LOG_DEBUG(e, i) aid_log_debug(__FILE__, __func__, __LINE__, (e), (i));
inline void
aid_log_debug(
    char const *fn,
    char const *func,
    int lineNo,
    int err,
    char const *i)
{
    if (aid_log.debug) {
        aid_log.debug(
            fn,
            func,
            lineNo,
            err,
            i);
    }
}

#define AID_LOG_INFO(e, i) aid_log_info(__FILE__, __func__, __LINE__, (e), (i));
inline void
aid_log_info(
    char const *fn,
    char const *func,
    int lineNo,
    int err,
    char const *i)
{
    if (aid_log.info) {
        aid_log.info(
            fn,
            func,
            lineNo,
            err,
            i);
    }
}

#define AID_LOG_ERROR(e, i) aid_log_error(__FILE__, __func__, __LINE__, (e), (i));
inline void
aid_log_error(
    char const *fn,
    char const *func,
    int lineNo,
    int err,
    char const *i)
{
    if (aid_log.error) {
        aid_log.error(
            fn,
            func,
            lineNo,
            err,
            i);
    }
}


void
aid_log_init(
    aid_log_func_t debug,
    aid_log_func_t info,
    aid_log_func_t error);


#endif
