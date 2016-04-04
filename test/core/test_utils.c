#include "test_core.h"

#include <stdio.h>

#include "aid/core/log.h"
#include "aid/core/utils.h"

/** Not currently implemented.
START_TEST(test_utils_b64_size)
{
    int res;
    size_t binsize1, binsize2, b64size;

    res = aid_utils_rand(
        NULL,
        (unsigned char *) &binsize1,
        sizeof(size_t));

    ck_assert_msg(res == 0, "Failed to generate a random size value.\n");

    res = aid_utils_b64url_encode_size(
        binsize1,
        &b64size);

    ck_assert_msg(res == 0, "Failed to calculate b64 encoded data size.\n");

    res = aid_utils_b64url_decode_size(
        b64size,
        &binsize2);

    ck_assert_msg(res == 0, "Failed to calculate b64 decoded data size.\n");
    ck_assert_msg(binsize1 == binsize2, "Size of the b64 decoded data was corrupted in computation.\n");
}
END_TEST


START_TEST(test_utils_b64_encode)
{
    char *b64;
    int res;
    size_t binsize = 212, b64size;
    unsigned char *bin1, *bin2;

    bin1 = malloc(binsize);
    ck_assert_msg(res == 0, "Failed to allocate memory for binary data.\n");

    res = aid_utils_rand(
        NULL,
        bin1,
        binsize);

    ck_assert_msg(res == 0, "Failed to generate random binary data.\n");

    res = aid_utils_b64url_encode_size(
        binsize,
        &b64size);

    ck_assert_msg(res == 0, "Failed to calculate base64 encoded size.\n");
    b64 = malloc(b64size);
    ck_assert_msg(b64 != NULL, "Failed to allocate memory for base64 encoded data.\n");

    res = aid_utils_b64url_encode(
        (unsigned char const *) bin1,
        binsize,
        b64,
        b64size);

    ck_assert_msg(res == 0, "Failed to b64url encode binary data.\n");
    bin2 = malloc(binsize);
    ck_assert_msg(bin2 != NULL, "Failed to allocate memory for base64 decoded data.\n");

    res = aid_utils_b64url_decode(
        (char const *) b64,
        b64size,
        bin2,
        binsize);

    ck_assert_msg(res == 0, "Failed to decode b64url encoded data.\n");
    res = memcmp(bin1, bin2, binsize);
    ck_assert_msg(res == 0, "B64url encoding and then decoding caused data corruption.\n");

    free(bin1);
    free(bin2);
    free(b64);
}
END_TEST
*/

START_TEST(test_utils_log_helper)
{
    int res;
    const char
        *filename = "some_file.name",
        *func = "some_function()",
        *info = "some info";
    int line = 123,
        state = -2;

    res = aid_utils_log_helper(
        filename,
        func,
        line,
        state,
        info);

    ck_assert_msg(res == 0, "Log helper failed to create logging string.\n");
    fprintf(stdout, "Sample log output: %s", aid_log_string);
}
END_TEST


Suite *
utils_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Core Utilities");

    /* Main test case */
    tc_core = tcase_create("Main");

//  tcase_add_test(tc_core, test_utils_b64_size);
//  tcase_add_test(tc_core, test_utils_b64_encode);
    tcase_add_test(tc_core, test_utils_log_helper);
    suite_add_tcase(s, tc_core);

    return s;
}
