#include "mutator.h"
#include <linux/limits.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/**
 * @brief We have to handle some variable length like 'curl' to 'Mozilla'.
 *        Some times it will cause some memory problems
 * @param ctx the packet context
 * @param found_ptr the position where we need to replace
 * @param target what we want to replace
 * @param replace replace to what?
 * @return int delta replace_len - target_len.
 */
static int perform_replacement(packet_ctx_t *ctx, uint8_t *found_ptr, const char *target, const char *replace) {
    int target_len = strlen(target);
    int replace_len = strlen(replace);
    int delta = replace_len - target_len;
    
    uint32_t old_total_len = ntohs(ctx->pkt.ip->tot_len);
    uint32_t new_total_len = old_total_len + delta;

    uint8_t *new_buf = (uint8_t *)malloc(new_total_len);
    if (!new_buf) {
        printf("[Error] OOM in mutator!\n");
        return 0; 
    }

    int head_len = found_ptr - ctx->raw_data;
    int tail_len = old_total_len - (head_len + target_len);

    // Copy Part A: IP Header + TCP Header + Payload first part
    memcpy(new_buf, ctx->raw_data, head_len);
    
    // Copy Part B: new string
    memcpy(new_buf + head_len, replace, replace_len);
    
    // Copy Part C: Payload last part
    if (tail_len > 0) {
        // raw_data + head + target_len
        memcpy(new_buf + head_len + replace_len, 
               ctx->raw_data + head_len + target_len, 
               tail_len);
    }

    // we put the buffer here, and when kernal sent the pkt,it will release the buffer.
    ctx->allocated_buffer = new_buf;
    ctx->verdict_data = new_buf;
    ctx->verdict_len = new_total_len;

    parse_packet(&ctx->pkt, new_buf, new_total_len);
    recalculate_checksums(&ctx->pkt);
    return delta;
}

int mutator_try_modify_http(packet_ctx_t *ctx) {
    if (!ctx->pkt.valid || ctx->pkt.payload_len == 0) return 0;

    const char *target = "curl/";
    const char *replace = "Mozilla/";
    
    if (ctx->pkt.payload_len < strlen(target)) return 0;

    uint8_t *found = NULL;
    for (uint32_t i = 0; i <= ctx->pkt.payload_len - strlen(target); i++) {
        if (memcmp(ctx->pkt.payload + i, target, strlen(target)) == 0) {
            found = ctx->pkt.payload + i;
            break;
        }
    }

    if (found) {
        int delta = perform_replacement(ctx, found, target, replace);
        if (delta != 0) {
             printf("[Mutator] Safe Replaced '%s' -> '%s' (Delta=%d)\n", target, replace, delta);
        }
        return delta;
    }
    return 0;
}

int disable_tcp_sack(packet_t *pkt) {
  if (!pkt->tcp) return 0;

    int len = pkt->tcp->doff * 4 - 20; 
    if (len <= 0) return 0;

    uint8_t *opt = (uint8_t *)(pkt->tcp + 1); 
    int i = 0;

    int modified = 0;

    while (i < len) {
        uint8_t kind = opt[i];
        
        // End of Option List
        if (kind == 0) break;
        
        // No-Operation
        if (kind == 1) {
            i++;
            continue;
        }

        // SACK Permitted (Kind=4, Len=2)
        if (kind == 4) {
            opt[i] = 1;   // NOP
            opt[i+1] = 1; // NOP
            
            modified = 1;
            i += 2;
        } else {
            if (i + 1 >= len) break;
            int opt_len = opt[i+1];
            if (opt_len < 2) break;
            i += opt_len;
        }
    }

    if (modified) {
        recalculate_checksums(pkt);
        return 1;
    }
    return 0;
}