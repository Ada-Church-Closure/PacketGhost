#include "strategies.h"
#include "../network/injector.h"
#include "../utils/csum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void inject_fake_rst(packet_ctx_t *ctx, int bad_checksum) {
  uint32_t ip_hdr_len = ctx->pkt.ip->ihl * 4;
  uint32_t tcp_hdr_len = ctx->pkt.tcp->doff * 4;
  uint32_t total_len = ip_hdr_len + tcp_hdr_len;

  uint8_t *rst_buf = (uint8_t *)malloc(total_len);
  if (!rst_buf)
    return;

  memcpy(rst_buf, ctx->raw_data, total_len);

  packet_t rst_pkt;
  parse_packet(&rst_pkt, rst_buf, total_len);

  rst_pkt.tcp->rst = 1;
  rst_pkt.tcp->ack = 0;
  rst_pkt.tcp->syn = 0;
  rst_pkt.tcp->fin = 0;
  rst_pkt.tcp->psh = 0;

  rst_pkt.ip->tot_len = htons(total_len);

  if (bad_checksum) {
    rst_pkt.tcp->check = 0xDEAD;
    recalculate_ip_checksums(rst_pkt.ip);
  } else {
    rst_pkt.payload_len = 0;
    recalculate_checksums(&rst_pkt);
  }

  printf("[Strategy] Injecting Fake RST (Bad Csum: %d)\n", bad_checksum);
  injector_send(rst_buf, total_len);

  free(rst_buf);
}

void inject_ttl_duplicate(packet_ctx_t *ctx, uint8_t new_ttl) {
  if (!ctx || !ctx->pkt.valid)
    return;

  uint16_t total_len = ntohs(ctx->pkt.ip->tot_len);
  if (total_len == 0 || total_len > ctx->raw_len) {
    return;
  }

  uint8_t *dup = (uint8_t *)malloc(total_len);
  if (!dup)
    return;

  memcpy(dup, ctx->raw_data, total_len);

  packet_t pkt;
  parse_packet(&pkt, dup, total_len);
  if (!pkt.valid) {
    free(dup);
    return;
  }

  pkt.ip->ttl = new_ttl;
  recalculate_checksums(&pkt);

  printf("[Strategy] Injecting TTL duplicate (ttl=%u) len=%u\n", new_ttl,
         total_len);
  injector_send(dup, total_len);

  free(dup);
}
