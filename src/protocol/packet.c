#include "packet.h"
#include <stddef.h>
#include <arpa/inet.h> // get ntohs method here.
#include "../utils/csum.h" // used to recalculate checksum.

void parse_packet(packet_t *pkt, uint8_t *data, uint32_t len) {
    pkt->valid = 0;
    pkt->ip = NULL;
    pkt->tcp = NULL;
    pkt->payload = NULL;
    pkt->payload_len = 0;

    if (len < sizeof(struct iphdr)) return;
    pkt->ip = (struct iphdr *)data;
    uint32_t ip_hl = pkt->ip->ihl * 4;
    if (len < ip_hl) return;

    if (pkt->ip->protocol != IPPROTO_TCP) return;
    pkt->tcp = (struct tcphdr *)(data + ip_hl);
    if (len < ip_hl + sizeof(struct tcphdr)) return;
    uint32_t tcp_hl = pkt->tcp->doff * 4;
    if (len < ip_hl + tcp_hl) return;

    pkt->payload = data + ip_hl + tcp_hl;
    uint16_t total_len = ntohs(pkt->ip->tot_len);

    if (total_len < ip_hl + tcp_hl) {
        pkt->payload_len = 0;
    } else {
        pkt->payload_len = total_len - ip_hl - tcp_hl;
    }
    
    uint32_t actual_buffer_left = len - ip_hl - tcp_hl;
    if (pkt->payload_len > actual_buffer_left) {
        pkt->payload_len = actual_buffer_left;
    }

    pkt->valid = 1;
}

void recalculate_checksums(packet_t *pkt) {
    if (!pkt->valid) return;

    // 1. 重算 IP 校验和 (只覆盖 IP 头)
    pkt->ip->check = 0; // 先清零
    pkt->ip->check = checksum(pkt->ip, pkt->ip->ihl * 4, 0);

    // 2. 重算 TCP 校验和 (覆盖 伪头部 + TCP头 + Payload)
    pkt->tcp->check = 0; // 先清零

    // 2.1 构造伪头部校验和
    // 技巧：我们可以手动加，不用构造结构体
    uint32_t sum = 0;
    sum += (pkt->ip->saddr >> 16) + (pkt->ip->saddr & 0xFFFF);
    sum += (pkt->ip->daddr >> 16) + (pkt->ip->daddr & 0xFFFF);
    sum += htons(IPPROTO_TCP);
    
    // TCP 总长度 = TCP头 + Payload
    uint16_t tcp_len = (pkt->tcp->doff * 4) + pkt->payload_len;
    sum += htons(tcp_len);

    // 2.2 计算 TCP 部分的校验和,TCP校验和我们是整个段来做计算的.
    // 注意：这里要把 TCP 头和 Payload 当作一段连续内存来算
    // 我们的 pkt->tcp 指向 TCP 头，它后面紧跟着就是 Payload
    // 所以直接传 pkt->tcp 指针，长度传 tcp_len 即可
    pkt->tcp->check = checksum(pkt->tcp, tcp_len, sum);
}