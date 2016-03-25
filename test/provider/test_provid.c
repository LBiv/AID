#include "test_provider.h"

#include "aid/provider/provid.h"
#include "aid/crypto/asymkeys.h"


START_TEST(test_provid_create_verify){


}
END_TEST

/**
START_TEST(test_provid_JSON) {


}
END_TEST
*/

Suite *
provid_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Provider ID token");

    tc_core = tcase_create("Main");

    tcase_add_test(tc_core, test_provid_create_verify);
    /**tcase_add_test(tc_core, test_provid_JSON);*/
    suite_add_tcase(s, tc_core);

    return s;
}
