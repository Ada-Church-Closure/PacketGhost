#ifndef MUTATOR_H
#define MUTATOR_H

#include "../common.h"

/**
 * @brief try to modify HTTP agent
 * @param ctx packet context
 * @return int delta the length change of packet. 
 */
int mutator_try_modify_http(packet_ctx_t *ctx);

/**
 * @brief Disable SACK in the header,because it's difficult to handle.
 * 
 * @param pkt The packet
 * @return int 1 = modified 0 = not modified.
 */
int disable_tcp_sack(packet_t* pkt);

#endif