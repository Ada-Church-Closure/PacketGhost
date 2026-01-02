#include "mutator.h"
#include <linux/limits.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

// TODO: use KMP or some good search algorithm.
int mutate_http_user_agent(packet_t *pkt) {
  if (!pkt->valid || !pkt->payload || pkt->payload_len == 0)
    return 0;

  // TODO: add more actions
  if (pkt->payload_len < 4)
    return 0;
  if (memcmp(pkt->payload, "GET", 3) != 0 &&
      memcmp(pkt->payload, "POST", 4) != 0 &&
      memcmp(pkt->payload, "HEAD", 4) != 0) {
    return 0;
  }

  const char *target = "curl/";
  // const char *replace = "hack/";
  const char *replace = "Mozilla/";

  size_t target_len = strlen(target);
  size_t replace_len = strlen(replace);

  int delta = replace_len - target_len;

  for (uint32_t i = 0; i < pkt->payload_len - target_len; i++) {
    if (memcmp(pkt->payload + i, target, target_len) == 0) {
      // memcpy(pkt->payload + i, replace, target_len);
      // printf("[Mutator] Replaced 'curl' with 'hack' at offset %u\n", i);
      // recalculate_checksums(pkt);
      // return 1;
      if (delta > 0) {
        // if the length changes
        // TODO:check total length of the nfq_get_payload
        memmove(pkt->payload + i + replace_len, pkt->payload + i + target_len,
                pkt->payload_len - (i + target_len));

        pkt->payload_len += delta;
        pkt->ip->tot_len = htons(ntohs(pkt->ip->tot_len) + delta);
      } else if (delta < 0) {
        memmove(pkt->payload + i + replace_len, pkt->payload + i + target_len,
                pkt->payload_len - (i + target_len));

        pkt->payload_len += delta;
        pkt->ip->tot_len = htons(ntohs(pkt->ip->tot_len) + delta);
      }
      memcpy(pkt->payload + i, replace, replace_len);
      printf("[Mutator] Replaced '%s' with '%s' (delta=%d)\n", target, replace,
             delta);
      recalculate_checksums(pkt);
      return 1;
    }
  }

  return 0;
}

int disable_tcp_sack(packet_t *pkt) {
  if (!pkt->tcp) return 0;

    int len = pkt->tcp->doff * 4 - 20; // Options 总长度
    if (len <= 0) return 0;

    uint8_t *opt = (uint8_t *)(pkt->tcp + 1); // 指向 Options 开始
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
            // 找到你了！把它改成 NOP (Kind=1)
            // 两个字节都要改：Kind=1, Len=1 (虽然 NOP 没 Len，但为了占位，我们填两个 NOP)
            opt[i] = 1;   // NOP
            opt[i+1] = 1; // NOP
            
            modified = 1;
            // printf("[Mutator] SACK Permitted removed from SYN.\n");
            i += 2;
        } else {
            // 其他选项，跳过 (读取长度字段)
            if (i + 1 >= len) break; // 越界保护
            int opt_len = opt[i+1];
            if (opt_len < 2) break;  // 长度异常保护
            i += opt_len;
        }
    }

    if (modified) {
        recalculate_checksums(pkt);
        return 1;
    }
    return 0;
}