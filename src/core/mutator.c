#include "mutator.h"
#include <string.h>
#include <stdio.h>

// TODO: use KMP or some good search algorithm.
int mutate_http_user_agent(packet_t *pkt) {
    if (!pkt->valid || !pkt->payload || pkt->payload_len == 0) return 0;

    // TODO: add more actions
    if (pkt->payload_len < 4) return 0;
    if (memcmp(pkt->payload, "GET", 3) != 0 && 
        memcmp(pkt->payload, "POST", 4) != 0 &&
        memcmp(pkt->payload, "HEAD", 4) != 0) {
        return 0; 
    }

    const char *target = "curl/";
    const char *replace = "hack/";
    size_t target_len = strlen(target);

    for (uint32_t i = 0; i < pkt->payload_len - target_len; i++) {
        if (memcmp(pkt->payload + i, target, target_len) == 0) {
            memcpy(pkt->payload + i, replace, target_len);
            printf("[Mutator] Replaced 'curl' with 'hack' at offset %u\n", i);
            recalculate_checksums(pkt);
            return 1;
        }
    }

    return 0;
}