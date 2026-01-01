#include <stdio.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <stdlib.h>

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

            session_t *sess = session_find(saddr, daddr, sport, dport);

            if (!sess && pkt.tcp->syn && !pkt.tcp->ack) {
                sess = session_create(saddr, daddr, sport, dport);
            }

            if (sess) {
                session_update(sess, pkt.tcp);
                if (sess->state == TCP_STATE_CLOSED) {
                    session_destroy(sess);
                    sess = NULL;
                    printf("[Session] Flow destroyed.\n");
                }
            }

            if (sess) {
                // 打印稍微美化一下，把数字变成可读的单词
                const char* state_str = "UNKNOWN";
                if (sess->state == TCP_STATE_SYN_SENT) state_str = "SYN_SENT";
                else if (sess->state == TCP_STATE_ESTABLISHED) state_str = "ESTABLISHED";
                else if (sess->state == TCP_STATE_FIN_WAIT) state_str = "FIN_WAIT";

                printf("[FLOW] %s | %u -> %u | Payload: %u\n", 
                       state_str, sport, dport, pkt.payload_len);
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