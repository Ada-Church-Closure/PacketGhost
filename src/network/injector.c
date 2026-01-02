#include "injector.h"
#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_raw_sock = -1;
// avoid spliting a pakcet many times.
// also you should set the rules of the firewalls.
#define PACKET_GHOST_MARK 0x100

int injector_init() {
  g_raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (g_raw_sock < 0) {
    perror("[Injector] Failed to create raw socket");
    return -1;
  }

  int one = 1;
  if (setsockopt(g_raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
    perror("[Injector] Failed to set IP_HDRINCL");
    return -1;
  }

  // set mark
  int mark = PACKET_GHOST_MARK;
  if (setsockopt(g_raw_sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) {
    perror("[Injector] Failed to set SO_MARK (Are you root?)");
    return -1;
  }

  printf("[Injector] Raw socket initialized.\n");
  return 0;
}

int injector_send(const uint8_t *packet_data, size_t len) {
  if (g_raw_sock < 0)
    return -1;

  struct iphdr *ip = (struct iphdr *)packet_data;
  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = ip->daddr;

  int sent = sendto(g_raw_sock, packet_data, len, 0, (struct sockaddr *)&dst,
                    sizeof(dst));

  if (sent < 0) {
    perror("[Injector] Send failed");
  }
  return sent;
}

void injector_close() {
  if (g_raw_sock >= 0) {
    close(g_raw_sock);
    g_raw_sock = -1;
  }
}
