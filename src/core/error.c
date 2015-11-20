#include "aid/core/error.h"

char const *aid_error_info(int errcode) {

    if (errcode > 0) {
        return "Function-specific return state, Not an error code";
    }

    if ( (-1) * errcode >= AID_ERR_NUM ) {
        return "Unknown error";
    }

    return aid_error_array[ (unsigned int) ((-1) * errcode) ];
}

char const *aid_error_array[AID_ERR_NUM] = {
    "AID_NO_ERROR [0]: No error",
    "AID_ERR_NULL_PTR [-1]: NULL pointer was passed into function",
    "AID_ERR_BAD_PARAM [-2]: Invalid parameter was passed into function",
    "AID_ERR_NO_MEM [-3]: Failed to allocate memory on the heap"
};
