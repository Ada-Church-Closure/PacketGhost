#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>

#include "core/mutator.h"
#include "protocol/packet.h"
#include "state/session.h"

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
  (void)nfmsg;
  (void)data;

  uint32_t id = 0;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  if (ph)
    id = ntohl(ph->packet_id);

  unsigned char *raw_data;
  int len = nfq_get_payload(nfa, &raw_data);

  uint32_t verdict = NF_ACCEPT;
  unsigned char *verdict_data = NULL;
  uint32_t verdict_len = 0;

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

      // TODO: If the packet is being retansmitted, we shouldn't change the delta.
      if (sess) {
        session_update(sess, pkt.tcp);
        int is_out_going = (saddr == sess->client_ip);
        // Client->Server
        if (is_out_going) {
          // Here,we disable SACK
          if (pkt.tcp->syn) {
            if (disable_tcp_sack(&pkt)) {
              verdict_data = raw_data;
              verdict_len = ntohs(pkt.ip->tot_len);
              printf("[NAT] SACK disabled for new flow.\n");
            }
          }


          // Revise the seqno
          if (sess->seq_delta != 0) {
            uint32_t old_seqno = ntohl(pkt.tcp->seq);
            pkt.tcp->seq = htonl(old_seqno + sess->seq_delta);
            recalculate_checksums(&pkt);
            verdict_data = raw_data;
            verdict_len = ntohs(pkt.ip->tot_len);
          }

          // Mutation
          if (pkt.payload_len > 0) {
            uint32_t old_len = pkt.payload_len;
            if (mutate_http_user_agent(&pkt)) {
              int current_delta = pkt.payload_len - old_len;
              sess->seq_delta += current_delta; // accumulate the delta
              verdict_data = raw_data;
              verdict_len = ntohs(pkt.ip->tot_len);
              printf("[NAT] Outgoing mutated. Total Delta: %d\n", sess->seq_delta);
            }
          }
            
          if (sess->state == TCP_STATE_CLOSED) {
            session_destroy(sess);
            sess = NULL;
            printf("[Session] Flow destroyed.\n");
          }
        } else {
          // Server -> Client
          // We only change the ack packet.
          if (pkt.tcp->ack && sess->seq_delta != 0) {
            uint32_t server_ack = ntohl(pkt.tcp->ack_seq);
            uint32_t fake_ack = server_ack - sess->seq_delta;
            
            pkt.tcp->ack_seq = htonl(fake_ack);
            recalculate_checksums(&pkt);
            
            verdict_data = raw_data;
            verdict_len = len;
            printf("[NAT] Incoming ACK Fixed: %u -> %u\n", server_ack, fake_ack);
          }
        }
      }
    }
  }
  // we send the verdict,and if the verdict_data is not null
  // kernel will use the verdict data to replace the old data.
  return nfq_set_verdict(qh, id, verdict, verdict_len, verdict_data);
}

int main() {
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  int fd, rv;
  char buf[4096] __attribute__((aligned));

  printf("Starting PacketGhost (Pure C)...\n");

  session_init();

  h = nfq_open();
  if (!h)
    return -1;

  nfq_unbind_pf(h, AF_INET);
  if (nfq_bind_pf(h, AF_INET) < 0)
    return -1;

  qh = nfq_create_queue(h, 0, &cb, NULL);
  if (!qh)
    return -1;

  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    return -1;

  fd = nfq_fd(h);
  while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
    nfq_handle_packet(h, buf, rv);
  }

  nfq_destroy_queue(qh);
  nfq_close(h);
  return 0;
}