#include "strategies.h"
#include "../network/injector.h"
#include "../utils/csum.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// 构造并发送一个伪造的 RST 包
// 参数 bad_checksum: 如果为 1，则故意写错校验和
void inject_fake_rst(packet_ctx_t *ctx, int bad_checksum) {
    uint32_t ip_hdr_len = ctx->pkt.ip->ihl * 4;
    uint32_t tcp_hdr_len = ctx->pkt.tcp->doff * 4;
    uint32_t total_len = ip_hdr_len + tcp_hdr_len; // RST 包通常没有 Payload

    uint8_t *rst_buf = (uint8_t *)malloc(total_len);
    if (!rst_buf) return;

    // 1. 复制头部 (IP + TCP)
    memcpy(rst_buf, ctx->raw_data, total_len);

    // 2. 解析以便修改
    packet_t rst_pkt;
    parse_packet(&rst_pkt, rst_buf, total_len);

    // 3. 修改 TCP Flags -> 设置 RST
    // 注意：Geneva 建议同时设置 RST 和 ACK，或者只设 RST，取决于防火墙特性
    rst_pkt.tcp->rst = 1;
    rst_pkt.tcp->ack = 0; 
    rst_pkt.tcp->syn = 0;
    rst_pkt.tcp->fin = 0;
    rst_pkt.tcp->psh = 0;

    // 4. 设置 SEQ
    // Geneva 发现，有时候 RST 的 SEQ 需要在当前 SEQ 范围内，有时需要稍微错开
    // 这里我们先用当前的 SEQ
    // rst_pkt.tcp->seq = ctx->pkt.tcp->seq; 

    // 5. 修正 IP 长度 (因为去掉了 Payload)
    rst_pkt.ip->tot_len = htons(total_len);
    
    // 6. 关键：处理校验和
    if (bad_checksum) {
        // 故意填一个垃圾值 (0xDEAD)
        rst_pkt.tcp->check = 0xDEAD;
        // IP 校验和最好是对的，否则可能在路由途中就被扔了，到不了 DPI
        recalculate_ip_checksums(rst_pkt.ip);
    } else {
        // 正常的校验和 (用于对比测试)
        rst_pkt.payload_len = 0;
        recalculate_checksums(&rst_pkt);
    }

    printf("[Strategy] Injecting Fake RST (Bad Csum: %d)\n", bad_checksum);
    injector_send(rst_buf, total_len);
    
    free(rst_buf);
}