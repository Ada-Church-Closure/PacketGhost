#ifndef CSUM_H
#define CSUM_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/ip.h>

// TCP Pseudo Header
// It's a conception here.
struct pseudo_header {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint8_t reserved;
  uint8_t protocol;
  uint16_t tcp_length;
};
/**
 * @brief calculate the checksum of buffer.
 * 
 * @param buffer 
 * @param len 
 * @param start_sum 
 * @return uint16_t checksum.
 */
static inline uint16_t checksum(void *buffer, size_t len, uint32_t start_sum) {
  uint32_t sum = start_sum;
  uint16_t *ptr = (uint16_t *)buffer;

  while (len > 1) {
    sum += *ptr++;
    len -= 2;
  }

  if (len > 0) {
    sum += *(uint8_t *)ptr;
  }

  
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (uint16_t)~sum;
}

static inline void recalculate_ip_checksums(struct iphdr *iph) {
  iph->check = 0;
  uint16_t len = iph->ihl * 4;
  iph->check = checksum(iph, len, 0);
}

#endif