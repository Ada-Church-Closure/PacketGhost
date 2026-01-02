#ifndef CSUM_H
#define CSUM_H

#include <stddef.h>
#include <stdint.h>

// 伪头部 (Pseudo Header)
// TCP/UDP 在计算校验和时，必须把 IP 地址也算进去
// 这是一个虚拟的头，并不真实存在于网络包中
struct pseudo_header {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint8_t reserved;
  uint8_t protocol;
  uint16_t tcp_length;
};

// 核心算法：计算 Buffer 的校验和
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

#endif