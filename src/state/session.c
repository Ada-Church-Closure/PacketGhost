#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static session_t *g_sessions = NULL;

void session_init() {
    g_sessions = NULL;
    printf("[Session] Table initialized.\n");
}

session_t* session_find(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport) {
    session_t *s = NULL;
    
    // client aspect
    struct flow_key_v4 k1;
    memset(&k1, 0, sizeof(k1)); 
    k1.src_ip = saddr;
    k1.dst_ip = daddr;
    k1.src_port = sport;
    k1.dst_port = dport;
    HASH_FIND(hh, g_sessions, &k1, sizeof(struct flow_key_v4), s);
    if (s) return s; 

    // server aspect
    struct flow_key_v4 k2;
    memset(&k2, 0, sizeof(k2));
    k2.src_ip = daddr;
    k2.dst_ip = saddr;
    k2.src_port = dport;
    k2.dst_port = sport;

    HASH_FIND(hh, g_sessions, &k2, sizeof(struct flow_key_v4), s);
    return s;
}

session_t* session_create(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport) {
    session_t *s = (session_t*)malloc(sizeof(session_t));
    if (!s) return NULL;

    memset(s, 0, sizeof(session_t));

    s->key.src_ip = saddr;
    s->key.dst_ip = daddr;
    s->key.src_port = sport;
    s->key.dst_port = dport;
    s->seq_delta = 0;
    s->client_ip = saddr;

    s->state = TCP_STATE_SYN_SENT;


    // HASH_ADD(hh, 头指针, Key字段名, Key长度, item指针)
    HASH_ADD(hh, g_sessions, key, sizeof(struct flow_key_v4), s);

    printf("[Session] New flow created: %u -> %u\n", sport, dport);
    return s;
}

void session_destroy(session_t *s) {
    if (!s) return;
    // 从哈希表中移除
    HASH_DELETE(hh, g_sessions, s);
    // 释放内存
    free(s);
}

void session_print_stats() {
    unsigned int count = HASH_COUNT(g_sessions);
    printf("[Session] Current active flows: %u\n", count);
}

void session_update(session_t *s, struct tcphdr *tcp) {
    if (!s || !tcp) return;

    if (tcp->rst) {
        s->state = TCP_STATE_CLOSED;
        printf("[Session] RST recerived, flow closed/\n");
        return;
    }

    switch (s->state) {
        case TCP_STATE_SYN_SENT:
            if (!tcp->syn && tcp->ack) {
                s->state = TCP_STATE_ESTABLISHED;
                printf("[Session] Handshake complete! State -> ESTABLISHED\n");
            }
            // This packet is from server.
            // We are midman.
            else if (tcp->syn && tcp->ack) {
                printf("[Session] SYN-ACK seen! Server is alive.\n");
            }
            break;
        case TCP_STATE_ESTABLISHED:
            if (tcp->fin) {
                s->state = TCP_STATE_FIN_WAIT;
                printf("[Session] FIN sent! State -> FIN_WAIT(1,2)\n");
            }
            break;
        case TCP_STATE_FIN_WAIT:
            if (tcp->ack || tcp->rst) {
                s->state = TCP_STATE_CLOSED;
                printf("[Session] Connection closing...\n");
            }
            break;
        default:
            break;
    }
}