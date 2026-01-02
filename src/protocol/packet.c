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

    pkt->ip->check = 0; 
    pkt->ip->check = checksum(pkt->ip, pkt->ip->ihl * 4, 0);

    pkt->tcp->check = 0; 

    uint32_t sum = 0;
    sum += (pkt->ip->saddr >> 16) + (pkt->ip->saddr & 0xFFFF);
    sum += (pkt->ip->daddr >> 16) + (pkt->ip->daddr & 0xFFFF);
    sum += htons(IPPROTO_TCP);
    
    uint16_t tcp_len = (pkt->tcp->doff * 4) + pkt->payload_len;
    sum += htons(tcp_len);

    pkt->tcp->check = checksum(pkt->tcp, tcp_len, sum);
}