#ifndef PACKET_H
#define PACKET_H

// The packet.h and packet.c are mainly handling how to deal with a packet, we parse
// it and get the headers of the packet.
#include <stdint.h>
#include <netinet/ip.h>  
#include <netinet/tcp.h> 

typedef struct {
    // This is Zero Copy!
    struct iphdr *ip;
    struct tcphdr *tcp;
    
    uint8_t *payload;
    uint32_t payload_len;

    int valid; 
} packet_t;

/**
 * @brief we have packet_t structure, and we parse it here.
 * 
 * @param pkt the NULL packet is passed into this function.
 * @param data the memory we need to parse.
 * @param len the length of the memory we need to parse.
 */
void parse_packet(packet_t *pkt, uint8_t *data, uint32_t len);

/**
 * @brief Everytime we change the structure or content of TCP segment, we need to recalculate the checksum and put it into the TCP segment.
 * 
 * @param pkt The packet needs to be recalculate
 */
void recalculate_checksums(packet_t *pkt);

#endif