#include "aid/core/log.h"

__thread aid_log_t aid_log =
{
    NULL,
    NULL,
    NULL
};


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

