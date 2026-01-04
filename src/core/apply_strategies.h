#ifndef APPLY_STRATEGIES_H
#define APPLY_STRATEGIES_H

#include "../common.h"

/**
 * @brief apply the fake RST strategy, first we send a fake RST and then we let kernal send the true packet.
 * 
 * @param ctx 
 * @return int 0 let the kernal send.
 */
int apply_fake_RST_strategy(packet_ctx_t *ctx);

/**
 * @brief Inject a TTL-decoy duplicate for DPI confusion while allowing the
 *        original packet to continue. This reflects a Geneva-style strategy
 *        where an early-expiring copy is sent with a small TTL.
 * @return int 0 -> do not block original (we just injected a decoy)
 */
int apply_ttl_decoy_strategy(packet_ctx_t *ctx);


#endif
