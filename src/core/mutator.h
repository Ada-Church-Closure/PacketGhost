#ifndef MUTATOR_H
#define MUTATOR_H

#include "../protocol/packet.h"

/**
 * @brief Try to alter the content of HTTP User-Agent.
 * @param pkt The structure after revision.
 * @return int 1 = revised，0 = not revised
 */
int mutate_http_user_agent(packet_t *pkt);

#endif