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
    "AID_ERR_RETURN [-1]: An error return propagated down the callstack",
    "AID_ERR_NULL_PTR [-2]: NULL pointer was passed into function",
    "AID_ERR_BAD_PARAM [-3]: Invalid parameter was passed into function",
    "AID_ERR_NO_MEM [-4]: Failed to allocate memory on the heap",
    "AID_ERR_RNG [-5]: Error generating random values",
    "AID_ERR_CRYPTO [-6]: Error occurred in the cryptographic library",
    "AID_ERR_COMMON [-7]: Error occurred in the common library",
    "AID_ERR_COMMON [-8]: Error occurred in the data library"
};
