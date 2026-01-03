#ifndef STRATEGIES_H
#define STRATEGIES_H

#include "../common.h"

/**
 * @brief construct a fake RST packet to let the DPI device to give up on listening this session.
 * 
 * @param ctx 
 * @param bad_checksum 1:construct fake RST 2:normal recalculate checksum.
 */
void inject_fake_rst(packet_ctx_t *ctx, int bad_checksum);


#endif