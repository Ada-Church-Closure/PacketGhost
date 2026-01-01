#ifndef PACKET_H
#define PACKET_H

// The packet.h and packet.c are mainly handling how to deal with a packet, we parse
// it and get the headers of the packet.
#include <stdint.h>
#include <netinet/ip.h>  // Linux 原生 IP 头定义
#include <netinet/tcp.h> // Linux 原生 TCP 头定义

// 定义一个结构体来承载解析结果
typedef struct {
    // 指向原始数据的指针 (不要 free 它们，它们指向的是内核缓冲区)
    // This is Zero Copy!
    struct iphdr *ip;
    struct tcphdr *tcp;
    
    // 指向 Payload (应用层数据) 的指针
    uint8_t *payload;
    // Payload 的长度
    uint32_t payload_len;

    // 解析是否成功 (1=成功, 0=失败)
    int valid; 
} packet_t;

// API: 传入原始数据和长度，填好 pkt 结构体
void parse_packet(packet_t *pkt, uint8_t *data, uint32_t len);

/**
 * @brief Everytime we change the structure or content of TCP segment, we need to recalculate the checksum and put it into the TCP segment.
 * 
 * @param pkt The packet needs to be recalculate
 */
void recalculate_checksums(packet_t *pkt);

#endif