#include "../src/utils/minunit.h"
#include "../src/utils/csum.h"
#include "test_utils.h"

// We simply use 1 + 2 and the reverse bits are 0xFFFC.
static char* test_checksum_simple() {
    uint16_t data[] = { 0x0001, 0x0002 };
    uint16_t sum = checksum(data, 4, 0);
    mu_assert("Checksum math error", sum == 0xFFFC);
    return 0;
}

char* test_checksum_suite() {
    mu_run_test(test_checksum_simple);
    return 0;
}
