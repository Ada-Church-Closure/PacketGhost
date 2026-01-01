#include <stdio.h>
#include "../src/utils/minunit.h"

#include "test_utils.h"
#include "test_packet.h"

int tests_run = 0;

static char* all_tests() {
    char *msg = test_checksum_suite();
    if (msg) return msg;

    msg = test_packet_suite();
    if (msg) return msg;

    return 0;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    printf("Running PacketGhost Test Suite...\n");
    
    char *result = all_tests();
    
    if (result != 0) {
        printf("\033[1;31mFAILED: %s\033[0m\n", result);
    } else {
        printf("\033[1;32mALL TESTS PASSED\033[0m\n");
    }
    printf("Total tests run: %d\n", tests_run);

    return result != 0;
}