#include "aid/core/log.h"

static __thread aid_log_t aid_log= {
    NULL,    
    NULL,
    NULL
};

void
aid_log_init(
    aid_log_func debug,
    aid_log_func info,
    aid_log_func error)
{
    aid_log->debug = debug;
    aid_log->info = info;
    aid_log->error = error;
}
    
