#include "packet.h"
#include <stddef.h>
#include <arpa/inet.h> // 为了 ntohs

void parse_packet(packet_t *pkt, uint8_t *data, uint32_t len) {
    // 1. 初始化：先假设包是坏的
    pkt->valid = 0;
    pkt->ip = NULL;
    pkt->tcp = NULL;
    pkt->payload = NULL;
    pkt->payload_len = 0;

    // ===========================
    // 解析 IP 头
    // ===========================
    // 检查 1: 长度是否够一个最小的 IP 头 (20字节)
    if (len < sizeof(struct iphdr)) return;
    
    // 强转指针：现在的 data 就是 IP 头
    pkt->ip = (struct iphdr *)data;

    // 计算 IP 头实际长度 (IHL * 4)
    uint32_t ip_hl = pkt->ip->ihl * 4;

    // 检查 2: 长度是否够完整的 IP 头 (防止 IHL 字段被篡改导致越界)
    if (len < ip_hl) return;

    // ===========================
    // 解析 TCP 头
    // ===========================
    // 检查 3: 必须是 TCP 协议
    if (pkt->ip->protocol != IPPROTO_TCP) return;

    // 这一步是指针运算的核心：
    // TCP 头的位置 = 数据起始地址 + IP 头长度
    pkt->tcp = (struct tcphdr *)(data + ip_hl);

    // 检查 4: 剩余长度是否够一个最小的 TCP 头 (20字节)
    if (len < ip_hl + sizeof(struct tcphdr)) return;

    // 计算 TCP 头实际长度 (Data Offset * 4)
    uint32_t tcp_hl = pkt->tcp->doff * 4;

    // 检查 5: 剩余长度是否够完整的 TCP 头
    if (len < ip_hl + tcp_hl) return;

    // ===========================
    // 定位 Payload (数据部分)
    // ===========================
    pkt->payload = data + ip_hl + tcp_hl;
    
    // 计算 Payload 长度 = IP包总长度 - IP头长 - TCP头长
    // 注意：一定要用 ntohs 把网络字节序转为主机字节序
    uint16_t total_len = ntohs(pkt->ip->tot_len);
    
    // 安全防御：如果 IP 头里写的总长度比实际捕获的还大，说明包被截断了或者有问题
    if (total_len < ip_hl + tcp_hl) {
        pkt->payload_len = 0;
    } else {
        pkt->payload_len = total_len - ip_hl - tcp_hl;
    }
    
    // 再次安全防御：确保 payload_len 不会超过实际 buffer 的剩余长度
    // (防止读取 buffer 溢出)
    uint32_t actual_buffer_left = len - ip_hl - tcp_hl;
    if (pkt->payload_len > actual_buffer_left) {
        pkt->payload_len = actual_buffer_left;
    }

    // 全部检查通过，标记为有效
    pkt->valid = 1;
}