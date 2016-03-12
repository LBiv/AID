#ifndef AID_CORE_LOG
#define AID_CORE_LOG

#include "aid/core/error.h"

#include <errno.h>

#define AID_LOG_DEBUG(errorcode, info)    do {errorcode; if(aid_log->debug) aid_log->debug(__FILE__, __func__, __LINE__, errno, aid_error_info(errorcode), info);} while(0) 
#define AID_LOG_INFO(errorcode, info)     do {errorcode; if(aid_log->info) aid_log->info(__FILE__, __func__, __LINE__, errno, aid_error_info(errorcode), info);} while(0)
#define AID_LOG_ERROR(errorcode, info)    do {errorcode; if(aid_log->error) aid_log->error(__FILE__, __func__, __LINE__, errno, aid_error_info(errorcode), info);} while(0)

typedef void (*aid_log_func_t)(
    char const *,   // filename
    char const *,   // function name
    int,            // line number
    int,            // errno
    char const *,   // state/error info
    char const *);  // specific log info

typedef struct {
    aid_log_func debug;
    aid_log_func info;
    aid_log_func error;
} aid_log_t;


void
aid_log_init(
    aid_log_func debug,
    aid_log_func info,
    aid_log_func error);


#endif
