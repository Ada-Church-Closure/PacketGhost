#include <stdio.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>

#include "protocol/packet.h"
#include "state/session.h"

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    (void)nfmsg; (void)data;

    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) id = ntohl(ph->packet_id);

    unsigned char *raw_data;
    int len = nfq_get_payload(nfa, &raw_data);

    if (len >= 0) {
        packet_t pkt;
        parse_packet(&pkt, raw_data, len);

        if (pkt.valid) {
            uint32_t saddr = ntohl(pkt.ip->saddr);
            uint32_t daddr = ntohl(pkt.ip->daddr);
            uint16_t sport = ntohs(pkt.tcp->source);
            uint16_t dport = ntohs(pkt.tcp->dest);

            // 1. 查找会话
            session_t *sess = session_find(saddr, daddr, sport, dport);
            
            // 2. 如果没找到，且是 SYN 包，创建新会话
            if (!sess && pkt.tcp->syn && !pkt.tcp->ack) {
                sess = session_create(saddr, daddr, sport, dport);
            }

            // 3. 打印状态
            if (sess) {
                printf("[FLOW] State: %d | %u:%u -> %u:%u\n", 
                       sess->state, sport, dport, saddr, daddr);
            } else {
                // 没找到会话也不是 SYN，可能是无状态的包或者 ACK 扫描
                printf("[DROP?] Unknown flow packet.\n");
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main() {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd, rv;
    char buf[4096] __attribute__ ((aligned));

    printf("Starting PacketGhost (Pure C)...\n");

    // 初始化会话表
    session_init();

    h = nfq_open();
    if (!h) return -1;

    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) return -1;

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) return -1;

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) return -1;

    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}