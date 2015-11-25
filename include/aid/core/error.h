#ifndef AID_CORE_ERROR
#define AID_CORE_ERROR

#define AID_ERR_NUM          4

#define AID_NO_ERROR         0
#define AID_ERR_NULL_PTR    -1
#define AID_ERR_BAD_PARAM   -2
#define AID_ERR_NO_MEM      -3


extern char const *aid_error_array[AID_ERR_NUM];


char const *
aid_error_info(int errcode);

#endif
