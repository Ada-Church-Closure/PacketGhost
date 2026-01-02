#ifndef FRAGMENTER_H
#define FRAGMENTER_H

#include "../common.h"

/**
 * @brief try to fragment the packet.
 * 
 * @param ctx packet context. 
 * @return int 1: fragment successfully main should drop the pkt.
               0: failed main should ACCEPT the pkt.
 */
int try_fragment_http(packet_ctx_t *ctx);

#endif