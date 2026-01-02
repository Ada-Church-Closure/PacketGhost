#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "protocol/packet.h"
#include "state/session.h"
/**
 * @brief Packet Context
 * 
 */
typedef struct {
    // Raw data only for read
    struct nfq_q_handle *qh;
    uint32_t id;
    uint8_t *raw_data;
    int raw_len;

    // after parsing
    packet_t pkt;
    
    // state
    session_t *sess;
    int is_outgoing; 

    // verdict result
    uint8_t *verdict_data; // point to the data which will be send to the kernal
    uint32_t verdict_len;
    
    // memory management
    uint8_t *allocated_buffer; 

} packet_ctx_t;

#endif