#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>

#include "common.h"
#include "core/fragmenter.h"
#include "core/mutator.h"
#include "protocol/packet.h"
#include "state/session.h"
#include "network/injector.h"

static void process_outgoing(packet_ctx_t *ctx) {
  // Ban SACK, this is simple.
  if (ctx->pkt.tcp->syn) {
    if (disable_tcp_sack(&(ctx->pkt))) {
      ctx->verdict_data = ctx->raw_data;
      ctx->verdict_len = ntohs(ctx->pkt.ip->tot_len);
      printf("[NAT] SACK disabled for new flow.\n");
    }
  }

  // TODO:make it more strong, at first, we use tcp segment fragment here.
  if (try_fragment_traffic(ctx)) {
    ctx->verdict = NF_DROP;
    ctx->verdict_data = NULL;
    ctx->verdict_len = 0;
    printf("[NAT] Packet fragmented & Original dropped.\n");
    return;
  }

  int current_delta = mutator_try_modify_http(ctx);

  if (current_delta != 0) {
    if (ctx->sess->ua_modified == 0) {
      ctx->sess->seq_delta += current_delta;
      ctx->sess->ua_modified = 1;
      printf("[NAT] Outgoing mutated. Total Delta: %d\n", ctx->sess->seq_delta);
    } else {
      printf("[NAT] Retransmission detected. Delta kept at: %d\n",
             ctx->sess->seq_delta);
    }
  }

  uint32_t seq_correction = ctx->sess->seq_delta - current_delta;

  if (seq_correction != 0 || current_delta != 0) {
    if (seq_correction != 0) {
      uint32_t old_seq = ntohl(ctx->pkt.tcp->seq);
      ctx->pkt.tcp->seq = htonl(old_seq + seq_correction);
    }
    uint16_t ip_tot_len = ntohs(ctx->pkt.ip->tot_len);
    uint16_t ip_hdr_len = ctx->pkt.ip->ihl * 4;
    uint16_t tcp_hdr_len = ctx->pkt.tcp->doff * 4;
    ctx->pkt.payload_len = ip_tot_len - ip_hdr_len - tcp_hdr_len;
    recalculate_checksums(&ctx->pkt);

    if (ctx->verdict_data == NULL) {
      ctx->verdict_data = ctx->raw_data;
      ctx->verdict_len = ntohs(ctx->pkt.ip->tot_len);
    }
  }
}

static void process_incoming(packet_ctx_t *ctx) {
  if (ctx->pkt.tcp->ack && ctx->sess->seq_delta != 0) {
    uint32_t server_ack = ntohl(ctx->pkt.tcp->ack_seq);
    uint32_t fake_ack = server_ack - ctx->sess->seq_delta;

    ctx->pkt.tcp->ack_seq = htonl(fake_ack);
    recalculate_checksums(&ctx->pkt);

    ctx->verdict_data = ctx->raw_data;
    ctx->verdict_len = ctx->raw_len;
  }
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
  (void)nfmsg;
  (void)data;

  packet_ctx_t ctx = {0};
  ctx.qh = qh;

  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  if (ph)
    ctx.id = ntohl(ph->packet_id);

  ctx.raw_len = nfq_get_payload(nfa, &ctx.raw_data);
  if (ctx.raw_len < 0)
    return nfq_set_verdict(qh, ctx.id, NF_ACCEPT, 0, NULL);

  parse_packet(&ctx.pkt, ctx.raw_data, ctx.raw_len);
  if (!ctx.pkt.valid)
    return nfq_set_verdict(qh, ctx.id, NF_ACCEPT, 0, NULL);

  uint32_t saddr = ntohl(ctx.pkt.ip->saddr);
  uint32_t daddr = ntohl(ctx.pkt.ip->daddr);
  uint16_t sport = ntohs(ctx.pkt.tcp->source);
  uint16_t dport = ntohs(ctx.pkt.tcp->dest);

  ctx.sess = session_find(saddr, daddr, sport, dport);
  if (!ctx.sess && ctx.pkt.tcp->syn && !ctx.pkt.tcp->ack) {
    ctx.sess = session_create(saddr, daddr, sport, dport);
  }

  if (ctx.sess) {
    session_update(ctx.sess, ctx.pkt.tcp);
    ctx.is_outgoing = (saddr == ctx.sess->client_ip);

    if (ctx.is_outgoing)
      process_outgoing(&ctx);
    else
      process_incoming(&ctx);
  }

  if (ctx.sess && ctx.sess->state == TCP_STATE_CLOSED) {
    session_destroy(ctx.sess);
    printf("[Session] Flow destroyed.\n");
  }

  uint32_t final_verdict = NF_ACCEPT;
  int ret = nfq_set_verdict(qh, ctx.id, final_verdict, ctx.verdict_len,
                            ctx.verdict_data);

  if (ctx.allocated_buffer) {
    free(ctx.allocated_buffer);
  }

  return ret;
}

int main() {

  if (injector_init() < 0) {
    return -1;
  }
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

  injector_close();
  return 0;
}