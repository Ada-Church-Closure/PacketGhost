#ifndef FRAGMENTER_H
#define FRAGMENTER_H

#include "../common.h"

#define OUT_OF_ORDER_INJECTION 1

/**
 * @brief try to fragment the packet.
 *        we also introduce split Client Hello SNI splition here to handle https's problems.
 * @param ctx packet context. 
 * @return int 1: fragment successfully main should drop the pkt.
               0: failed main should ACCEPT the pkt.
 */
int try_fragment_traffic(packet_ctx_t *ctx);

#endif