#include "aid/core/log.h"

__thread aid_log_t aid_log =
{
    NULL,
    NULL,
    NULL
};

__thread char aid_log_string[512];


void
aid_log_init(
    aid_log_func_t debug,
    aid_log_func_t info,
    aid_log_func_t error)
{
    aid_log.debug = debug;
    aid_log.info = info;
    aid_log.error = error;
}

void
aid_log_debug(
    char const *fn,
    char const *func,
    int lineNo,
    int err,
    char const *i);

void
aid_log_info(
    char const *fn,
    char const *func,
    int lineNo,
    int err,
    char const *i);

void
aid_log_error(
    char const *fn,
    char const *func,
    int lineNo,
    int err,
    char const *i);
