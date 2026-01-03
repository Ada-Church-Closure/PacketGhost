#include <stdio.h>

#include "strategies.h"
#include "apply_strategies.h"
#include "../utils/protocol_types.h"



int apply_fake_RST_strategy(packet_ctx_t *ctx) {
    if (!ctx->pkt.valid || ctx->pkt.payload_len <= 2) return 0;
    
    // 检测到敏感流量 (HTTP/TLS)
    int is_target = 0;
    if (is_http_request(ctx->pkt.payload, ctx->pkt.payload_len)) is_target = 1;
    else if (is_tls_hello(ctx->pkt.payload, ctx->pkt.payload_len)) is_target = 1;

    if (is_target) {
        // Geneva Strategy 1: [TCP:flags:R]-duplicate(tamper{checksum:bad}, send)-send
        
        // 1. 先注入一个坏的 RST
        inject_fake_rst(ctx, 1); // 1 = bad checksum

        // 2. 再放行原始包 (不做分片，直接 ACCEPT)
        // 注意：这里我们不需要丢弃原包，直接返回 0 让 main.c ACCEPT 即可
        // 或者显式返回一个代码告诉 main 不要修改
        
        printf("[Geneva] Strategy Applied: Fake RST + Original Packet\n");
        
        // 返回 0 表示“我不拦截/不修改原包，请放行”
        // 但我们已经偷偷注入了一个 RST 出去了
        return 0; 
    }
    return 0;
}
