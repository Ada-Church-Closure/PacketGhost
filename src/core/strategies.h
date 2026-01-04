#ifndef STRATEGIES_H
#define STRATEGIES_H

#include "../common.h"

#ifndef TTL_DECOY_VALUE
#define TTL_DECOY_VALUE 2
#endif

/**
 * @brief construct a fake RST packet to let the DPI device to give up on listening this session.
 * 
 * @param ctx 
 * @param bad_checksum 1:construct fake RST 2:normal recalculate checksum.
 */
void inject_fake_rst(packet_ctx_t *ctx, int bad_checksum);

/**
 * @brief duplicate and inject the current packet but with a modified IP TTL.
 *        Commonly used as a Geneva-style TTL decoy that expires before the
 *        destination but can be seen by on-path DPI.
 * @param ctx packet context of the original packet
 * @param new_ttl the TTL value to set on the duplicate
 */
void inject_ttl_duplicate(packet_ctx_t *ctx, uint8_t new_ttl);


#endif
