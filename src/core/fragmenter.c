#include "fragmenter.h"
#include "../network/injector.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief Construct and send a slice
 * 
 * @param ctx packet context
 * @param seq  the seqno of the packet
 * @param payload  
 * @param payload_len 
 */
static void send_slice(packet_ctx_t *ctx, uint32_t seq, uint8_t *payload, int payload_len) {
    uint32_t ip_hdr_len = ctx->pkt.ip->ihl * 4;
    uint32_t tcp_hdr_len = ctx->pkt.tcp->doff * 4;
    uint32_t headers_len = ip_hdr_len + tcp_hdr_len;
    
    uint32_t total_len = headers_len + payload_len;

    uint8_t *slice = (uint8_t *)malloc(total_len);
    if (!slice) return;
    memcpy(slice, ctx->raw_data, headers_len);
    if (payload_len > 0) {
        memcpy(slice + headers_len, payload, payload_len);
    }
    packet_t slice_pkt;
    parse_packet(&slice_pkt, slice, total_len);
    slice_pkt.ip->tot_len = htons(total_len);
    slice_pkt.ip->id = htons(ntohs(ctx->pkt.ip->id) + 1);
    slice_pkt.tcp->seq = htonl(seq);
    slice_pkt.payload_len = payload_len; 
    recalculate_checksums(&slice_pkt);
    injector_send(slice, total_len);
    free(slice);
}

int try_fragment_http(packet_ctx_t *ctx) {
    if (!ctx->pkt.valid || ctx->pkt.payload_len <= 2) return 0;
    // TODO: handle more specificly about the http method
    if (!ctx->pkt.tcp->psh) return 0;
    // [Header] [P1 P2] [P3 P4 ... Pn]
    // Chunk 1: [Header] [P1 P2]
    // Chunk 2: [Header] [P3 ... Pn]
    int split_pos = 2;
    uint8_t *payload_start = ctx->pkt.payload;
    uint32_t original_seq = ntohl(ctx->pkt.tcp->seq);
    printf("[Fragmenter] Splitting %d bytes into %d + %d\n", 
           ctx->pkt.payload_len, split_pos, ctx->pkt.payload_len - split_pos);
    // send the first slice
    send_slice(ctx, original_seq, payload_start, split_pos);

    // send the second slice
    send_slice(ctx, original_seq + split_pos, 
               payload_start + split_pos, 
               ctx->pkt.payload_len - split_pos);
    return 1;
}
