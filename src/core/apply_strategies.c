#include <stdio.h>

#include "strategies.h"
#include "apply_strategies.h"
#include "../utils/protocol_types.h"



int apply_fake_RST_strategy(packet_ctx_t *ctx) {
    if (!ctx->pkt.valid || ctx->pkt.payload_len <= 2) return 0;
    
    int is_target = 0;
    if (is_http_request(ctx->pkt.payload, ctx->pkt.payload_len)) is_target = 1;
    else if (is_tls_hello(ctx->pkt.payload, ctx->pkt.payload_len)) is_target = 1;

    if (is_target) {
        inject_fake_rst(ctx, 1); // 1 = bad checksum
        printf("[Geneva] Strategy Applied: Fake RST + Original Packet\n");
        return 1; 
    }
    return 0;
}

int apply_ttl_decoy_strategy(packet_ctx_t *ctx) {
    if (!ctx || !ctx->pkt.valid) return 0;

    int is_target = 0;
    if (is_http_request(ctx->pkt.payload, ctx->pkt.payload_len)) is_target = 1;
    else if (is_tls_hello(ctx->pkt.payload, ctx->pkt.payload_len)) is_target = 1;
    if (!is_target) return 0;
    uint8_t decoy_ttl = TTL_DECOY_VALUE; 
    inject_ttl_duplicate(ctx, decoy_ttl);
    printf("[Geneva] Strategy Applied: TTL Decoy (ttl=%u) + Original\n", decoy_ttl);
    return 1; 
}
